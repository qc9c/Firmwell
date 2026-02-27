import re
import os
import string
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def clean_string(s: str) -> str:
    """Remove non-printable characters from a string, keeping only ASCII printable chars."""
    printable = set(string.printable)
    return ''.join(filter(lambda x: x in printable, s))

IGNORE_PATH = ('/bin', '/usr/bin', '/sbin', '/usr/sbin', '/etc/ld.so.cache')

class LogPreprocessing:
    """Preprocesses strace log files into structured process information.

    Performs three main tasks:
    1. Parses each strace log line into structured events (pid, syscall name, args, return value, error info).
    2. Groups events by process (pid), tracking binary name, syscall history, and segfault status.
    3. Aggregates metadata across all processes (file accesses, failed accesses, network interfaces,
       nvram accesses, chdir paths, parent-child relationships).

    Binary names are initially set to the initial binary; updated via execve syscalls,
    and inherited by child processes created through fork/vfork/clone.
    """
    
    def __init__(self, tracelog_dict: dict, initial_binary: str, enable_basic_create: bool = True):
        """Initialize the log preprocessor.

        Args:
            tracelog_dict: Maps log file indices ("0", "1", ...) to lists of trace log lines.
            initial_binary: The initial binary name for the root process.
            enable_basic_create: Whether to enable ioctl-based file creation fixes.
        """
        self.tracelog_dict = tracelog_dict
        self.initial_binary = initial_binary
        self.enable_basic_create = enable_basic_create
        
        # Pattern for complete syscall lines: pid syscall(args) = retval [errno=N (msg)]
        self.syscall_pattern = re.compile(
            r'^(?P<pid>\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*?)\)\s+=\s+(?P<retval>.*?)(?:\s+errno=(?P<errno>\d+)\s+\((?P<error_msg>[^)]+)\))?$'
        )
        
        # Pattern for incomplete syscall lines (no return value, e.g. blocking recv)
        self.incomplete_syscall_pattern = re.compile(
            r'^(?P<pid>\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*?)\)$'
        )
        
        # Pattern for signal lines (e.g. SIGSEGV)
        self.signal_pattern = re.compile(
            r'^---\s+(?P<signal>SIG[A-Z]+)\s+(?P<details>.*)---$'
        )
        
        self.exit_codes = {}  # pid -> exit code mapping
    
    def _parse_retval(self, retval_str: str):
        """Parse a return value string into an integer (decimal or hex) or return as string."""
        try:
            if "0x" in retval_str:
                return int(retval_str.split()[0], 16)
            else:
                return int(retval_str.split()[0])
        except ValueError:
            return retval_str

    def _parse_syscall_args(self, syscall_name: str, args_str: str):
        """Parse syscall arguments into a structured dict based on syscall type.

        Args:
            syscall_name: Name of the syscall (e.g. open, ioctl, execve).
            args_str: Raw argument string from the trace line.

        Returns:
            dict: Parsed arguments with syscall-specific keys (e.g. 'file', 'device', 'target').
        """
        args = self._split_args(clean_string(args_str))
        result = {"raw_args": args}
        
        def extract_device(s):
            pattern = r'^[^,]*,[^,]*,\{"?([^"\x00]*)'
            match = re.match(pattern, s)
            if match:
                return match.group(1)
            return None
        
        # Extract key arguments based on syscall type
        if syscall_name in ["open", "openat"]:
            if syscall_name == "open" and len(args) > 0:
                # open("file", flags, ...)
                result["file"] = self._extract_str_arg(args[0])
            elif syscall_name == "openat" and len(args) > 1:
                # openat(dirfd, "file", flags, ...)
                result["file"] = self._extract_str_arg(args[1])
        
        elif syscall_name == "access" and len(args) > 0:
            # access("file", mode)
            result["file"] = self._extract_str_arg(args[0])
        
        elif syscall_name in ["stat", "stat64"] and len(args) > 0 and "fstat" not in syscall_name:
            # stat("file", struct stat*)
            result["file"] = self._extract_str_arg(args[0])
        
        elif syscall_name == "chdir" and len(args) > 0:
            # chdir("dir")
            result["file"] = self._extract_str_arg(args[0])
        
        elif syscall_name == "ioctl" and len(args) > 0:
            # ioctl(fd, request, ...)
            result['device'] = extract_device(args_str)
        
        elif syscall_name == "execve" and len(args) > 0:
            # execve("path", argv[], envp[])
            result["target"] = self._extract_str_arg(args[0])
            
        return result
    
    def _extract_str_arg(self, arg: str):
        """Extract the first quoted string from a syscall argument."""
        match = re.search(r'"([^"]*)"', arg)
        if match:
            return match.group(1)
        return ""
    
    def _split_args(self, args_str: str):
        """Split a syscall argument string by commas, respecting quotes and brackets.

        Args:
            args_str: Raw argument string.

        Returns:
            list: Individual argument strings.
        """
        args = []
        current_arg = ""
        in_quotes = False
        bracket_level = 0
        
        for char in args_str:
            if char == ',' and not in_quotes and bracket_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                if char == '"' and (not current_arg or current_arg[-1] != '\\'):
                    in_quotes = not in_quotes
                elif char == '{' or char == '[' or char == '(':
                    bracket_level += 1
                elif char == '}' or char == ']' or char == ')':
                    bracket_level -= 1
                current_arg += char
        
        if current_arg:
            args.append(current_arg.strip())
        
        return args

    def _process_file_access(self, event, filename, accessed_files, failed, access_nvram=None, ignore_hidden=True):
        """Process a file access syscall (open/stat/access) and classify the result.

        Args:
            event: Parsed syscall event dict.
            filename: File path being accessed.
            accessed_files: Set of successfully accessed file paths.
            failed: Set of file paths that failed to be accessed.
            access_nvram: Optional dict tracking NVRAM file accesses.
            ignore_hidden: Whether to skip hidden files (starting with '.').
        """
        if not filename:
            return
            
        basefilename = os.path.basename(filename)
        # Skip hidden files and empty paths
        if ignore_hidden and (not filename.strip() or not basefilename or basefilename.startswith(".")):
            return

        retval = event['retval']
        if isinstance(retval, int):
            if retval >= 0:
                accessed_files.add(filename)
            elif retval < 0:
                # Skip files in ignored system paths
                if os.path.basename(filename) and filename.startswith(IGNORE_PATH):
                    return

                if basefilename not in accessed_files:
                    failed.add(filename)
                    # Track NVRAM file access failures
                    if access_nvram is not None and "gh_nvram" in filename:
                        access_nvram[filename] = None

    def _handle_child_process(self, parent_pid, child_pid, parent_to_children, child_to_parent, get_proc):
        """Register a child process and inherit the parent's binary name."""
        parent_rec = get_proc(parent_pid)
        child_rec = get_proc(child_pid)
        child_rec["binary"] = parent_rec["binary"]
        parent_to_children.setdefault(parent_pid, []).append(child_pid)
        child_to_parent[child_pid] = parent_pid
    
    def parse_files(self, use_bash=False):
        """Parse all trace log files and build structured process and metadata information.

        Args:
            use_bash: If True, skip tracelog_dict['0'] (shell wrapper) and start from '1' for initial PID.

        Returns:
            tuple: (process_info, meta_info)
                process_info (dict): Per-PID logs with binary name, syscall history, and crash status.
                meta_info (dict): Aggregated metadata across all processes.
        """
        # Initialize tracking collections
        miss_interfaces = set()
        access_interfaces = set()
        failed = set()
        folders = set()
        access_nvram = dict()
        chdir_set = set()
        accessed_files = set()
        parent_to_children = {}
        child_to_parent = {}
        
        # meta_info
        meta_info = {
            "process_map": {},      # pid -> executable name
            "parent_map": {},       # pid -> parent_pid
            "file_accesses": defaultdict(list),  # file_path -> [(pid, syscall, result), ...]
            "network_ops": [],      # List of network-related operations
            "ipc_ops": [],          # List of IPC-related operations
            "failed_syscalls": defaultdict(list),  # pid -> [(syscall_name, args, error), ...]
            "error_counts": defaultdict(int),  # error_type -> count
            "miss_interfaces": miss_interfaces,
            "access_interfaces": access_interfaces,
            "failed": failed,
            "folders": folders,
            "access_nvram": access_nvram,
            "chdir_set": chdir_set,
            "accessed_files": accessed_files,
            "parent_to_children": parent_to_children,
            "child_to_parent": child_to_parent
        }
        
        # Determine initial_pid from trace logs (respecting use_bash flag)
        self.initial_pid = None
        sorted_keys = sorted(self.tracelog_dict.keys(), key=lambda x: int(x))
        
        for key in sorted_keys:
            # When use_bash is True, skip key '0' (shell wrapper log)
            if use_bash and key == '0':
                continue
            
            lines = self.tracelog_dict[key]
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                m = re.match(r'^(?P<pid>\d+)', line)
                if m:
                    try:
                        self.initial_pid = int(m.group("pid"))
                    except ValueError:
                        self.initial_pid = None
                    break
            if self.initial_pid is not None:
                break
        
        if self.initial_pid is None:
            raise ValueError("Could not determine initial PID from trace logs")
        
        # Initialize process info for the root process
        process_info = {}
        process_info[self.initial_pid] = {
            "binary": self.initial_binary,
            "logs": [],
            "segfaulted": False
        }
        
        meta_info["initial_pid"] = self.initial_pid
        meta_info["process_map"][self.initial_pid] = self.initial_binary
        
        def get_proc(pid):
            if pid not in process_info:
                process_info[pid] = {
                    "binary": "unknown",
                    "logs": [],
                    "segfaulted": False
                }
            return process_info[pid]
        
        def get_default_pid(lines):
            # Extract the first PID found in the log lines (used as default for the file)
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                m = re.match(r'^(?P<pid>\d+)', line)
                if m:
                    try:
                        return int(m.group("pid"))
                    except ValueError:
                        pass
            return None
        
        # Limit to first 100 trace log files to prevent excessive processing
        if len(self.tracelog_dict) > 100:
            self.tracelog_dict = dict(sorted(self.tracelog_dict.items(), key=lambda x: int(x[0]))[:100])
        
        # Process all trace log files
        for key, lines in self.tracelog_dict.items():
            default_pid = get_default_pid(lines)
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if not line:
                    i += 1
                    continue

                parsed = False
                event = None
                cur_pid = default_pid
                
                # Check for signal lines (e.g. SIGSEGV)
                signal_match = self.signal_pattern.match(line)
                if signal_match:
                    signal_info = signal_match.groupdict()
                    event = {
                        "call": signal_info["signal"],
                        "details": signal_info["details"],
                        "error": True,
                        "is_signal": True,
                        "args": "",
                        "error_msg": signal_info["details"],
                        "original_syscall": line  # Add original text
                    }
                    # get last line pid
                    syscall_match = self.syscall_pattern.match(lines[i - 1])
                    if syscall_match:
                        match_dict = syscall_match.groupdict()
                        try:
                            cur_pid = int(match_dict["pid"])
                        except ValueError:
                            cur_pid = default_pid
                    parsed = True
                    
                # Try matching as a complete syscall line
                if not parsed:
                    syscall_match = self.syscall_pattern.match(line)
                    if syscall_match:
                        match_dict = syscall_match.groupdict()
                        try:
                            cur_pid = int(match_dict["pid"])
                        except ValueError:
                            cur_pid = default_pid
                        
                        syscall_name = match_dict["syscall"]
                        args_str = match_dict["args"]
                        retval_str = match_dict["retval"]
                        errno = match_dict.get("errno")
                        error_msg = match_dict.get("error_msg")
                        
                        retval = self._parse_retval(retval_str)

                        # Build the event dict
                        event = {
                            "pid": cur_pid,
                            "call": syscall_name,
                            "args": clean_string(args_str).split(","),
                            "retval": retval,
                            "error": False,
                            "error_msg": "",
                            "original_syscall": line  # Add original text
                        }
                        
                        # Record error information if present
                        if errno:
                            event["error"] = True
                            event["errno"] = int(errno)
                            event["error_msg"] = error_msg
                            error_code = error_msg.upper().replace(" ", "_")
                            meta_info["error_counts"][error_code] += 1
                            meta_info["failed_syscalls"][cur_pid].append((syscall_name, args_str, (error_code, int(errno))))
                        
                        # Parse syscall-specific arguments
                        parsed_args = self._parse_syscall_args(syscall_name, args_str)
                        for key, value in parsed_args.items():
                            event[key] = value


                        
                        self._handle_specific_syscall(syscall_name, event, cur_pid, accessed_files, failed, folders,
                                                      miss_interfaces, access_interfaces, chdir_set, access_nvram, parent_to_children,
                                                      child_to_parent, get_proc, meta_info, line)
                        
                        parsed = True
                
                # Try matching as an incomplete syscall (e.g. blocking recv)
                if not parsed:
                    incomplete_match = self.incomplete_syscall_pattern.match(line)
                    if incomplete_match:
                        match_dict = incomplete_match.groupdict()
                        try:
                            cur_pid = int(match_dict["pid"])
                        except ValueError:
                            cur_pid = default_pid
                        
                        syscall_name = match_dict["syscall"]
                        args_str = match_dict["args"]
                        
                        # Handle incomplete recv/recvfrom/_newselect (blocking calls)
                        if syscall_name in ["recv", "recvfrom", "_newselect"]:
                            # Split args into a list for consistent handling
                            # if syscall_name == "_newselect":
                            #     #  [5] 
                            #     fd_match = re.match(r'\[(\d+)\]', args_str.split(',')[0])
                            #     if fd_match:
                            #         fd = fd_match.group(1)
                            # else:
                            # recv/recvfromfd
                            """
                            1836 _newselect([],[5],[],{tv_sec = 60,tv_usec = 0}) =  = 0x00000001 ([],[5],[],{tv_sec = 59,tv_usec = 999998})
1836 _newselect([5],[],[],{tv_sec = 60,tv_usec = 0})
                            """
                            fd = args_str.split(',')
                            

                            event = {
                                "pid": cur_pid,
                                "call": syscall_name,
                                "args": fd if fd else [],
                                "retval": "incomplete",
                                "error": False,
                                "error_msg": "",
                                "incomplete": True,
                                "original_syscall": line
                            }

                            parsed_args = self._parse_syscall_args(syscall_name, args_str)
                            for key, value in parsed_args.items():
                                event[key] = value

                            # Record as a network operation
                            meta_info["network_ops"].append({
                                "pid": cur_pid,
                                "syscall": syscall_name,
                                "args": fd if fd else [],
                                "result": "incomplete",
                                "incomplete": True
                            })
                            
                            parsed = True
                       
                        if syscall_name in ["exit", "exit_group"]:
                            try:
                                exit_code = int(args_str)
                                event = {
                                    "pid": cur_pid,
                                    "call": syscall_name,
                                    "args": [args_str],
                                    "retval": "incomplete",
                                    "error": False,
                                    "error_msg": "",
                                    "incomplete": True,
                                    "original_syscall": line
                                }
                                
                                self.exit_codes[cur_pid] = exit_code
                                proc = get_proc(cur_pid)
                                proc["exit_code"] = exit_code
                                
                                parsed = True
                            except (ValueError, IndexError):
                                pass

                # Handle fork/clone/vfork (may have non-standard formatting)
                if not parsed and ("clone(" in line or "fork(" in line or "vfork(" in line):
                    try:
                        cur_pid = int(re.match(r'^(?P<pid>\d+)', line).group("pid"))
                    except Exception:
                        cur_pid = default_pid
                    
                    # Extract child PID from the return value
                    child_pid = None
                    m = re.search(r'\)\s+=\s+(\d+)', line)
                    if m:
                        try:
                            child_pid = int(m.group(1))
                        except ValueError:
                            child_pid = None
                    
                    # If not found inline, check subsequent lines (up to 3)
                    if child_pid is None:
                        j = i + 1
                        while j < i + 3:
                            if j < len(lines):
                                next_line = lines[j].strip()
                                if next_line.startswith("= "):
                                    try:
                                        child_pid = int(next_line.split("= ")[1])
                                        break
                                    except (ValueError, IndexError):
                                        pass
                            j += 1
                            

                    # Register the child process if both PIDs are known
                    if child_pid is not None and cur_pid is not None:
                        syscall_name = None
                        if "clone(" in line:
                            syscall_name = "clone"
                        elif "fork(" in line:
                            syscall_name = "fork"
                        elif "vfork(" in line:
                            syscall_name = "vfork"
                        
                        event = {
                            "pid": cur_pid,
                            "call": syscall_name,
                            "retval": child_pid,
                            "details": line,
                            "error": False,
                            "error_msg": "",
                            "args": "",
                            "original_syscall": line  # Add original text
                        }
                        
                        self._handle_child_process(cur_pid, child_pid, parent_to_children, child_to_parent, get_proc)
                        meta_info["parent_map"][child_pid] = cur_pid

                        # Fall back to initial PID if current PID is not in process map
                        try:
                            meta_info["process_map"][cur_pid]
                        except KeyError:
                            logger.warning(f"Parent PID {cur_pid} not in process_map, falling back to initial PID")
                            cur_pid = self.initial_pid


                        if cur_pid not in meta_info["process_map"]:
                            meta_info["process_map"][cur_pid] = "unknown"
                        
                        meta_info["process_map"][child_pid] = meta_info["process_map"][
                            cur_pid]  # set parent binary to child
                        
                        parsed = True
                
                # Append the parsed event to the process record
                if parsed and event is not None:
                    if cur_pid is None:
                        cur_pid = default_pid
                    if cur_pid is not None:
                        proc_rec = get_proc(cur_pid)
                        proc_rec["logs"].append(event)
                    if event.get("call") == "SIGSEGV" and cur_pid is not None:
                        get_proc(cur_pid)["segfaulted"] = True
                i += 1
        
        # Remove files from failed set if they were successfully opened elsewhere
        failed = {f for f in failed if os.path.basename(f) not in accessed_files}
        meta_info["failed"] = failed

        return process_info, meta_info
    
    def _handle_specific_syscall(self, syscall_name, event, cur_pid, accessed_files, failed, folders,
                                miss_interfaces, access_interfaces, chdir_set, access_nvram, parent_to_children,
                                child_to_parent, get_proc, meta_info, line):
        """Handle syscall-specific logic for metadata collection and error tracking.

        Args:
            syscall_name: Name of the syscall.
            event: Parsed event dict.
            cur_pid: Current process ID.
        """
        # File access syscalls
        if syscall_name in ["open", "openat"]:
            filename = event.get("file", "")
            if filename:
                self._process_file_access(event, filename, accessed_files, failed, access_nvram)
                meta_info["file_accesses"][filename].append((cur_pid, syscall_name, event['retval']))
        
        elif syscall_name in ["stat", "stat64"] and "fstat" not in syscall_name:
            filename = event.get("file", "")
            if filename:
                self._process_file_access(event, filename, accessed_files, failed)
                meta_info["file_accesses"][filename].append((cur_pid, syscall_name, event['retval']))

        
        elif syscall_name == "access":
            filename = event.get("file", "")
            if filename:
                self._process_file_access(event, filename, accessed_files, failed)
                meta_info["file_accesses"][filename].append((cur_pid, syscall_name, event['retval']))

        
        elif syscall_name == "chdir":
            filename = event.get("file", "")
            if filename:
                if isinstance(event['retval'], int) and event['retval'] < 0:
                    folders.add(filename)
                else:
                    if filename in folders:
                        folders.remove(filename)
                    if filename.startswith("/"):
                        chdir_set.add(filename)
        
        elif syscall_name == "ioctl":
            device = event.get("device", "")
            if device:
                net_dev = clean_string(device)
                event['device'] = net_dev
                access_interfaces.add(net_dev)
                
                if event.get("error") and "No such device" in event.get("error_msg", ""):
                    if net_dev not in miss_interfaces:
                        miss_interfaces.add(net_dev)
                    
                logger.debug(f"ioctl event: {event}")

        elif syscall_name == "setsocketopt":
            pass
            # # Specifically handle SO_BINDTODEVICE
            # if 'SO_BINDTODEVICE' in result['optname']:
            #     result['device'] = result['optval']
            #     if 'error' in result and result['error']['code'] == 'ENODEV':
            #         result['error_type'] = 'missing_network_device'
        elif syscall_name == "_newselect":
            pass
        
        elif syscall_name == "execve":
            target = event.get("target", "")
            if target and not event.get("error"):
                proc = get_proc(cur_pid)
                proc["binary"] = target
                meta_info["process_map"][cur_pid] = target
        
        elif syscall_name in ["clone", "fork", "vfork"]:
            retval = event.get("retval")
            if isinstance(retval, int) and retval > 0:
                self._handle_child_process(cur_pid, retval, parent_to_children, child_to_parent, get_proc)
                meta_info["parent_map"][retval] = cur_pid

                # Fall back to initial PID if current PID is not in process map
                try:
                    meta_info["process_map"][cur_pid]
                except KeyError:
                    logger.warning(f"Parent PID {cur_pid} not in process_map, falling back to initial PID")
                    cur_pid = self.initial_pid


                if cur_pid not in meta_info["process_map"]:
                    meta_info["process_map"][cur_pid] = "unknown"

                meta_info["process_map"][retval] = meta_info["process_map"][cur_pid]  # set parent binary to child
        
        # Track network operations
        if syscall_name in ["socket", "bind", "connect", "listen", "accept"]:
            meta_info["network_ops"].append({
                "pid": cur_pid,
                "syscall": syscall_name,
                "args": event.get("raw_args", []),
                "result": event.get("retval")
            })
        
        # Track IPC operations
        if syscall_name in ["mmap", "shmat", "shmget", "msgget", "msgsnd", "msgrcv"]:
            meta_info["ipc_ops"].append({
                "pid": cur_pid,
                "syscall": syscall_name,
                "args": event.get("raw_args", []),
                "result": event.get("retval")
            })

        # Track exit codes
        elif syscall_name in ["exit", "exit_group"]:
            try:
                exit_code = int(event.get("args", ["0"])[0])
                self.exit_codes[cur_pid] = exit_code
                proc = get_proc(cur_pid)
                proc["exit_code"] = exit_code
            except (ValueError, IndexError):
                pass

    def _identify_ipc_relationships(self, process_info, meta_info):
        """Identify IPC relationships between processes."""
        # Group IPC operations by identifiers (files, sockets, etc.)
        ipc_groups = defaultdict(list)
        
        for op in meta_info["ipc_ops"]:
            # Extract IPC identifier based on syscall type
            identifier = self._extract_ipc_identifier(op)
            if identifier:
                ipc_groups[identifier].append(op)
        
        # Identify setter and getter processes for each IPC group
        for identifier, ops in ipc_groups.items():
            write_ops = [op for op in ops if self._is_write_operation(op["syscall"])]
            read_ops = [op for op in ops if self._is_read_operation(op["syscall"])]
            
            if write_ops and read_ops:
                setter_pids = set(op["pid"] for op in write_ops)
                getter_pids = set(op["pid"] for op in read_ops)
                
                meta_info["ipc_relationships"] = meta_info.get("ipc_relationships", [])
                meta_info["ipc_relationships"].append({
                    "identifier": identifier,
                    "setter_pids": setter_pids,
                    "getter_pids": getter_pids
                })
    
    def _extract_ipc_identifier(self, op):
        """Extract IPC identifier from operation."""
        syscall = op["syscall"]
        args = op["args"]
        
        # Simplified extraction logic
        if syscall in ["shmget", "shmat"]:
            # Extract shared memory key
            return f"shm:{args[0]}" if args else None
        elif syscall in ["msgget", "msgsnd", "msgrcv"]:
            # Extract message queue key
            return f"msg:{args[0]}" if args else None
        
        return None
    
    def _is_write_operation(self, syscall):
        """Check if syscall is a write operation."""
        return syscall in ["write", "writev", "pwrite", "msgsnd", "shmat"]
    
    def _is_read_operation(self, syscall):
        """Check if syscall is a read operation."""
        return syscall in ["read", "readv", "pread", "msgrcv", "shmat"]
        
    def classify_failed_files(self, failed: set):
        """Classify failed file accesses into categories: proc, dev, sys, nvram, and other.

        Args:
            failed: Set of file paths that failed to be accessed.

        Returns:
            tuple: (miss_proc, miss_dev, miss_sys, miss_nvram, other)
        """
        miss_proc, miss_dev, miss_sys, other = set(), set(), set()
        miss_nvram = dict()
        
        blacklist = ["bin/", ".ko", "ld.so.cache", "ld.so.preload"]
        for file in failed:
            if any(black in file for black in blacklist):
                continue
            if file.startswith("/lib") or file.startswith("/usr/lib"):
                continue
            if file.startswith("/proc"):
                pattern = r'^/proc/(\d+)/stat$'
                if re.match(pattern, file):
                    continue
                pattern = r'^/proc/(\d+)/cmdline$'
                if re.match(pattern, file):
                    continue
                pattern = r'^/proc/(\d+)$'
                if re.match(pattern, file):
                    continue
                miss_proc.add(file)
            elif file.startswith("/sys"):
                miss_sys.add(file)
            elif file.startswith("/dev"):
                miss_dev.add(file)
            elif file.startswith("/gh_nvram"):
                name = file.replace("/gh_nvram/", "")
                miss_nvram[name] = None
            else:
                other.add(file)
        return miss_proc, miss_dev, miss_sys, miss_nvram, other



if __name__ == "__main__":
    import pickle
    with open('/tmp/data.pkl', 'rb') as f:
        tracelog_dict = pickle.load(f)
        preprocessor = LogPreprocessing(tracelog_dict=tracelog_dict, initial_binary="aaa")
        process_info, meta_info = preprocessor.parse_files(use_bash=True)
        print(process_info)
    
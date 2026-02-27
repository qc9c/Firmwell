import re
import os
from collections import defaultdict, namedtuple
import logging
import subprocess
import struct
import socket
from firmwell.backend.Utils import find_files
from firmwell.backend.reason_fix.ipc_reason.analyzer_factory import analyze_binary

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


WEB_EXTS = ["html", "htm", "xhtm", "jhtm", "cgi", "xml", "js", "wss",
            "php", "php4", "php3", "phtml", "rss", "svg", "dll",
            "asp", "aspx", "axd", "asx", "asmx", "ashx", "cfm", "swf", "stm"]

IGNORE_PATH = ('/bin', '/usr/bin', '/sbin', '/usr/sbin', '/etc/ld', '/etc/TZ', "/tmp", "/var", "/etc")

ErrorPattern = namedtuple('ErrorPattern', ['name', 'scope', 'category', 'description'])


class ErrorLocator:
    """
    Analyzes preprocessed logs to detect errors based on patterns.

    """
    
    def __init__(self, process_info, meta_info, initial_pid=None, fixed_errors=None, fs_path="", cwd="/", env=None,
                 network_info=None, found_peer_process=True, tracelog_dict=None,
                 enable_fix_in_peer=True, enable_infer=True, enable_create=True, enable_reuse=True,enable_enhance_create=True, FileSystem=None):
        """
        Initialize with process information and metadata.

        """
        self.process_info = process_info
        self.meta_info = meta_info
        self.initial_pid = initial_pid
        self.fixed_errors = fixed_errors or []
        self.fs_path = fs_path
        self.cwd = cwd
        self.env = env
        self.ori_network_info = network_info or {"eth0", "192.168.1.1"}
        self.found_peer_process = found_peer_process
        self.tracelog_dict = tracelog_dict
        
        
        self.enable_fix_in_peer = enable_fix_in_peer
        self.enable_infer = enable_infer
        self.enable_create = enable_create
        self.enable_reuse = enable_reuse
        self.enable_enhance_create = enable_enhance_create
        self.FileSystem = FileSystem
    
    def is_strategy_enabled(self, error_pattern):
        """Check whether the fix strategy for a given error pattern is enabled."""
        if error_pattern is None:
            return True
            
        category = error_pattern.get('category', '')
        fix_strategy = error_pattern.get('fix_strategy', '')
        path = error_pattern.get('path', '')
        
            
        if category == 'FIX-IN-PEER' and not self.enable_fix_in_peer:
            logger.debug(f"Skipping FIX-IN-PEER strategy for error: {error_pattern}")
            return False
        
        if category == 'INFER' and not self.enable_infer:
            logger.debug(f"Skipping INFER strategy for error: {error_pattern}")
            return False
        
        if (fix_strategy in ['create_system_file', 'create_network_device'] or category == 'CREATE') and not self.enable_create:
            logger.debug(f"Skipping CREATE strategy for error: {error_pattern}")
            return False
        
        if (fix_strategy and fix_strategy.startswith('reuse_')) and not self.enable_reuse:
            logger.debug(f"Skipping REUSE strategy for error: {error_pattern}")
            return False
        
        return True
    
    def _ip_to_machine_code(self, ip_str):
        """
        Convert IP address string to machine code for searching in binaries.
        
        Args:
            ip_str: IP address string (e.g., "127.0.0.1")
            
        Returns:
            bytes: Machine code representation of the IP address
        """
        try:
            # Convert IP string to integer and then to bytes (both endianness)
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            return (struct.pack("<I", ip_int), struct.pack(">I", ip_int))
        except Exception as e:
            logger.warning(f"Failed to convert IP {ip_str} to machine code: {e}")
            return (None, None)
    
    def _find_potential_binaries_by_addr(self, addr):
        """
        Find potential binaries that contain the given address string.
        
        Args:
            addr: Address string (e.g., "tcapi_sock", "127.0.0.1:2319", "/tmp/ubus.sock")
            
        Returns:
            set: Set of binary paths that potentially use this address
        """
        potential_binaries = set()
        
        executable_files = self.FileSystem.elf_files
        
        # Parse address to determine search strategy
        if ":" in addr and "." in addr:
            # IP:PORT format
            ip_part = addr.split(":")[0]
            port_part = addr.split(":")[1]
            
            # Search for IP in machine code format
            little_endian, big_endian = self._ip_to_machine_code(ip_part)
            
            # Search in each executable file
            for file_path in executable_files:
                if not os.path.isfile(file_path):
                    continue
                    
                # Check for machine code representation
                if little_endian:
                    cmd = f'xxd "{file_path}" 2>/dev/null | grep -q "{little_endian.hex()}"'
                    result = subprocess.run(cmd, shell=True)
                    if result.returncode == 0:
                        potential_binaries.add(file_path)
                        continue
                
                # Check for string representation
                strings = self._get_strings_of_file(file_path, ip_part)
                if strings:
                    potential_binaries.add(file_path)
                    continue
                    
                # Check for port
                strings = self._get_strings_of_file(file_path, port_part)
                if strings:
                    potential_binaries.add(file_path)
        else:
            # Unix socket or other string format
            search_str = os.path.basename(addr) if "/" in addr else addr
            
            for file_path in executable_files:
                if not os.path.isfile(file_path):
                    continue
                    
                strings = self._get_strings_of_file(file_path, search_str)
                if strings:
                    potential_binaries.add(file_path)
        
        logger.debug(f"Found {len(potential_binaries)} potential binaries for address {addr}")
        return potential_binaries
    
    def _get_strings_of_file(self, file_path, target_str):
        """Helper method to get strings from a file matching target string."""
        try:
            cmd = f'strings -a "{file_path}" 2>/dev/null | grep -F "{target_str}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.splitlines() if result.stdout else []
        except Exception as e:
            logger.warning(f"Error getting strings from {file_path}: {e}")
            return []
    
    def _analyze_binary_for_socket(self, binary_path, socket_addr):
        """
        Analyze a binary to check if it uses the given socket address.
        Runs analysis in subprocess with memory and time limits to prevent OOM.
        
        Args:
            binary_path: Path to the binary to analyze
            socket_addr: Socket address to search for
            
        Returns:
            bool: True if the binary uses this socket address
        """
        try:
            import json
            
            # Path to wrapper script
            wrapper_path = os.path.join(os.path.dirname(__file__), 'ipc_reason', 'analyze_binary_wrapper.py')
            
            # Build command with resource limits
            # ulimit -v sets virtual memory limit in KB (1GB = 1048576 KB)
            # ulimit -t sets CPU time limit in seconds (300s = 5 minutes)
            # Change to the parent directory to ensure imports work correctly
            parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(wrapper_path)))
            cmd = [
                'bash', '-c',
                f'cd {parent_dir} && ulimit -v 1048576 && ulimit -t 300 && python3 {wrapper_path} socket "{binary_path}" "{socket_addr}"'
            ]
            
            logger.debug(f"Running binary analysis with limits: {binary_path}")
            
            # Run with timeout (slightly more than ulimit timeout)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=310  # 5 minutes + 10 seconds buffer
            )
            
            if result.returncode != 0:
                logger.warning(f"Binary analysis failed for {binary_path}: return code {result.returncode}, stderr: {result.stderr}")
                return False
                
            # Parse JSON result
            output = json.loads(result.stdout.strip())
            if output.get('success'):
                uses_socket = output.get('uses_socket', False)
                if uses_socket:
                    logger.debug(f"Binary {binary_path} uses socket {socket_addr}")
                return uses_socket
            else:
                logger.warning(f"Binary analysis error for {binary_path}: {output.get('error', 'Unknown error')}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Binary analysis timed out for {binary_path} (>5 minutes)")
            return False
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse analysis output for {binary_path}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Failed to analyze binary {binary_path}: {e}")
            return False
    
    def _analyze_binary_for_shm(self, binary_path):
        """
        Analyze a binary to check if it uses shared memory IPC.
        Runs analysis in subprocess with memory and time limits to prevent OOM.
        
        Args:
            binary_path: Path to the binary to analyze
            
        Returns:
            bool: True if the binary uses shared memory IPC
        """
        try:
            import json
            
            # Path to wrapper script
            wrapper_path = os.path.join(os.path.dirname(__file__), 'ipc_reason', 'analyze_binary_wrapper.py')
            
            # Build command with resource limits
            # ulimit -v sets virtual memory limit in KB (1GB = 1048576 KB)
            # ulimit -t sets CPU time limit in seconds (300s = 5 minutes)
            # Change to the parent directory to ensure imports work correctly
            parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(wrapper_path)))
            cmd = [
                'bash', '-c',
                f'cd {parent_dir} && ulimit -v 1048576 && ulimit -t 300 && python3 {wrapper_path} shm "{binary_path}"'
            ]
            
            logger.debug(f"Running SHM binary analysis with limits: {binary_path}")
            
            # Run with timeout (slightly more than ulimit timeout)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=310  # 5 minutes + 10 seconds buffer
            )
            
            if result.returncode != 0:
                logger.warning(f"SHM binary analysis failed for {binary_path}: return code {result.returncode}, stderr: {result.stderr}")
                return False
                
            # Parse JSON result
            output = json.loads(result.stdout.strip())
            if output.get('success'):
                uses_shm = output.get('uses_shm', False)
                if uses_shm:
                    logger.debug(f"Binary {binary_path} uses shared memory IPC")
                return uses_shm
            else:
                logger.warning(f"SHM binary analysis error for {binary_path}: {output.get('error', 'Unknown error')}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.warning(f"SHM binary analysis timed out for {binary_path} (>5 minutes)")
            return False
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse SHM analysis output for {binary_path}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Failed to analyze binary for SHM {binary_path}: {e}")
            return False
    
    def _has_shm_id_file_access_before_crash(self, syscalls):
        """Check if syscalls show a file-open on a shm_id file shortly before a shmat failure.

        Detects the pattern where a process reads a shm_id file (via access/open/openat)
        and then calls shmat with an invalid ID, indicating the process itself manages
        the shared memory segment rather than a separate peer.

        Args:
            syscalls: List of parsed syscall events.

        Returns:
            bool: True if the shm_id file access pattern is found before a shmat crash.
        """
        # Find the shmat failure index
        shmat_index = -1
        for i, syscall in enumerate(syscalls):
            call = syscall.get("call", "")
            if call == "shmat":
                args = syscall.get("args", [])
                errno = syscall.get("errno", None)
                if args and len(args) >= 1 and args[0] == "-1" and errno == 22:
                    shmat_index = i
                    break
            # Also check ipc-style shmat (MIPS)
            if call == "ipc" and args and len(args) >= 1:
                try:
                    if int(args[0]) == 21:  # SHMAT
                        shmat_index = i
                        break
                except (ValueError, IndexError):
                    pass

        if shmat_index < 0:
            return False

        # Look back up to 10 syscalls for file-open access to a shm_id path
        file_open_calls = {"access", "open", "openat"}
        start = max(0, shmat_index - 10)
        for i in range(start, shmat_index):
            syscall = syscalls[i]
            call = syscall.get("call", "")
            if call in file_open_calls:
                args = syscall.get("args", [])
                for arg in args:
                    if isinstance(arg, str) and "shm_id" in arg:
                        logger.debug(f"Found shm_id file access at syscall index {i}: {call}({args})")
                        return True

        return False

    def _identify_shm_peer_process(self):
        """
        Identify the peer process that uses shared memory IPC.

        Returns:
            str or None: Path to the peer process binary
        """
        # Get list of executable files from filesystem
        executable_files = self.FileSystem.elf_files
        
        # Filter out common system libraries and web files
        filtered_files = [f for f in executable_files if 
                         ".so" not in f and 
                         "/lib/" not in f and 
                         "html" not in f and 
                         "www" not in f and 
                         "etc" not in f]
        
        logger.debug(f"Analyzing {len(filtered_files)} binaries for shared memory usage")
        
        # Analyze each binary for shared memory usage
        shm_binaries = []
        for binary in filtered_files:
            if self._analyze_binary_for_shm(binary):
                shm_binaries.append(binary)
                # For performance, return the first match if only analyzing one
                if len(shm_binaries) == 1:
                    logger.debug(f"Found single SHM binary: {binary}")
                    return binary
        
        if not shm_binaries:
            logger.warning("No binaries found using shared memory")
            return None
        
        if len(shm_binaries) == 1:
            return shm_binaries[0]
        
        # If multiple binaries use shared memory, try to narrow down
        # Priority: binaries with names suggesting they manage shared resources
        priority_keywords = ['manager', 'daemon', 'server', 'controller', 'monitor']
        for binary in shm_binaries:
            binary_name = os.path.basename(binary).lower()
            if any(keyword in binary_name for keyword in priority_keywords):
                logger.debug(f"Selecting priority SHM binary: {binary}")
                return binary
        
        # Return the first one if no priority match
        logger.debug(f"Returning first SHM binary from {len(shm_binaries)} candidates")
        return shm_binaries[0]
    
    def _identify_peer_process(self, socket_addr):
        """
        Identify the peer process that listens on or connects to the given socket address.
        
        Args:
            socket_addr: Socket address (Unix path or IP:PORT)
            
        Returns:
            str or None: Path to the peer process binary
        """
        # First, find potential binaries containing the address
        potential_binaries = self._find_potential_binaries_by_addr(socket_addr)
        
        if not potential_binaries:
            logger.warning(f"No potential binaries found for address {socket_addr}")
            return None
        
        logger.debug(f"Analyzing {len(potential_binaries)} potential binaries for {socket_addr}")
        
        
        if len(potential_binaries) == 1:
            return list(potential_binaries)[0]
        
        # Analyze each potential binary
        matching_binaries = []
        for binary in potential_binaries:
            if self._analyze_binary_for_socket(binary, socket_addr):
                matching_binaries.append(binary)
        
        if not matching_binaries:
            logger.warning(f"No binaries confirmed to use address {socket_addr}")
            return None
                
        # Return the first matching binary
        peer_process = matching_binaries[0]
        logger.debug(f"Identified peer process for {socket_addr}: {peer_process}")
        return peer_process

    def _is_same_error(self, error1: dict, error2: dict, fixed_nvram_keys: set) -> bool:
        """
        Determine if two error patterns represent the same error by comparing
        their key elements based on fix strategy type.
        
        Args:
            error1: First error pattern, new input
            error2: Second error pattern, previously detected error
        
        Returns:
            bool: True if the errors are the same, False otherwise
        """
        if error1 is None or error2 is None:
            return False
        
        # First check if fix strategies match
        if error1.get('fix_strategy') != error2.get('fix_strategy'):
            return False
            
        strategy = error1.get('fix_strategy')
        
        # Compare strategy-specific elements
        if strategy == "fill_file_content":
            return error1.get('path') == error2.get('path')
            
        elif strategy == "fill_ioctl_content":
            return error1.get('op') == error2.get('op')

        elif strategy == "fix_ipc_socket_service":
            return error1.get('socket_fd') == error2.get('socket_fd')

        elif strategy == "infer_nvram_value":
            return error1.get('miss_nvrams') in fixed_nvram_keys
            
        elif strategy == "infer_magic_bytes":
            return error1.get('path') == error2.get('path')
            
        elif strategy == "reuse_file":
            return error1.get('path') == error2.get('path')
            
        elif strategy == "create_network_device":
            # Compare sets of missing interfaces if present
            interfaces1 = error1.get("miss_interfaces")
            interfaces2 = error2.get("miss_interfaces")
            if isinstance(interfaces1, set) and isinstance(interfaces2, set):
                return interfaces1 == interfaces2
            return interfaces1 == interfaces2
            
        elif strategy == "reuse_cwd":
            return (error1.get('path') == error2.get('path') and
                    error1.get('cwd') == error2.get('cwd'))
                    
        elif strategy == "reuse_directory":
            return error1.get('path') == error2.get('path')
            
        elif strategy == "create_system_file":
            return error1.get('path') == error2.get('path')
            
        elif strategy == "reuse_so_files":
            # For .so files, we consider them the same if they target the same directory
            return error1.get('target_dir') == error2.get('target_dir')
        
        elif error1["description"] == "reuse_template":
            paths1 = set(error1.get("paths", [error1.get("path", "")]))
            paths2 = set(error2.get("paths", [error2.get("path", "")]))
            return bool(paths1 & paths2)  
            
        # Fallback comparison for other strategies
        return (error1.get('pid') == error1.get('pid') and 
                error1.get('syscall') == error2.get('syscall'))
                
    def _is_error_fixed(self, error_pattern: dict, saved_errors) -> bool:
        """
        Check if the current error has already been fixed in previous iterations.
        
        Args:
            error_pattern: The current error pattern to check
            saved_errors: List of previously detected errors
        
        Returns:
            bool: True if this specific error has been fixed before, False otherwise
        """
        if not saved_errors:
            return False
    
        fixed_nvram_keys = set()
        for fixed_error in self.fixed_errors:
            if fixed_error is not None and fixed_error.get("fix_strategy") == "infer_nvram_value":
                fixed_nvram_keys.update(fixed_error.get("miss_nvrams", set()))
        
        
        for previous_error in saved_errors:
            if self._is_same_error(error_pattern, previous_error, fixed_nvram_keys):
                return True
                
        return False

    def _check_last_sys_file_access(self, syscalls, last_n=50):
        """Check the last N syscalls for accesses to system files (/proc, /sys, /dev)."""
        if not syscalls:
            return None
            
        last_syscalls = syscalls[-last_n:]
        last_sys_file = None
        
        for syscall in reversed(last_syscalls):
            name = syscall.get("call")
            args = syscall.get("args", [])
            
            file_path = None
            if name == "open":
                file_path = args[0].strip('"') if args else None
            elif name == "openat":
                file_path = args[1].strip('"') if len(args) > 1 else None
            elif name in ["stat", "stat64", "access"]:
                file_path = args[0].strip('"') if args else None
                
            if file_path and file_path.startswith(("/proc", "/sys", "/dev")):
                # Skip per-process proc entries
                if re.match(r'^/proc/(\d+)/stat$', file_path) or \
                   re.match(r'^/proc/(\d+)/cmdline$', file_path) or \
                   re.match(r'^/proc/(\d+)$', file_path):
                    continue
                return file_path
                
        return None

    def locate_errors(self):
        """Locate the next unfixed error across all processes in priority order.

        Returns:
            dict or None: Error pattern dict describing the detected error and fix strategy,
            or None if no unfixed errors remain.
        """
        worklist = self._find_error_process_worklist(self.initial_pid)
        logger.debug(f"Found {len(worklist)} processes in worklist: {worklist}")
        
        last_sys_file = None
        for pid in worklist:
            if pid not in self.process_info:
                continue
                
            syscalls = self.process_info[pid].get('logs', [])
            failed_syscalls = [s for s in syscalls if s.get('exit') != 0 or s.get('crash')]
            if not failed_syscalls:
                continue
                
            last_sys_file = self._check_last_sys_file_access(syscalls, last_n=50)
            
            if last_sys_file is None:
                continue
            
            logger.debug(f"last_sys_file: {last_sys_file}")
            if last_sys_file and self.fixed_errors:
                last_error = self.fixed_errors[-1]
                logger.debug(f"last_error: {last_error}")
                if last_error is not None and (last_error.get("path") == last_sys_file and 
                    last_error.get("fix_strategy") == "fill_file_content"):
                    logger.debug(f"Found continued access to previously filled system file: {last_sys_file}")
                    error = {
                        "category": "INFER",
                        "description": "INFER_MAGIC",
                        "syscalls": [],
                        "path": last_sys_file,
                        "fix_strategy": "infer_magic_byte"
                    }
                    if self.is_strategy_enabled(error):
                        return error

        # Collect all previously fixed nvram keys
        fixed_nvram_keys = set()
        for fixed_error in self.fixed_errors:
            if fixed_error is not None and fixed_error.get("fix_strategy") == "infer_nvram_value":
                fixed_nvram_keys.update(fixed_error.get("miss_nvrams", set()))
        
        # Limit syscalls to last 1000 for each process
        for pid in worklist:
            if pid not in self.process_info:
                continue
                
            syscalls = self.process_info[pid].get('logs', [])
            if len(syscalls) > 1000:
                logger.debug(f"Limiting syscalls for process {pid} to last 1000 (total: {len(syscalls)})")
                self.process_info[pid]['logs'] = syscalls[-1000:]
        
        
        logger.debug(f"match network errors first")
        # find network errors first
        for pid in worklist:
            if pid not in self.process_info:
                logger.debug(f"Process {pid} not in process_info, skipping")
                continue
            
            # logger.debug(f"Analyzing failures for process {pid}")
            # candidate_errors = self._analyze_process_failures(pid)
            
            syscalls = self.process_info[pid]['logs']
            logger.debug(f"Analyzing process {pid} with {len(syscalls)} syscalls")
            
            candidate_errors = self._match_network_interfaces_error(syscalls)
            if candidate_errors:
                logger.debug(f"Found network interface error: {candidate_errors}")

                if isinstance(candidate_errors, list):
                    logger.debug(f"Found {len(candidate_errors)} candidate errors for process {pid}")
                    for error in candidate_errors:
                        if not self._is_error_fixed(error, self.fixed_errors):
                            logger.debug(f"Process {pid} found unfixed error: {error}")
                            return error
                elif candidate_errors and not self._is_error_fixed(candidate_errors, self.fixed_errors):
                    logger.debug(f"Process {pid} found unfixed single error: {candidate_errors}")
                    return candidate_errors
                elif candidate_errors:
                    logger.debug(f"Error found for process {pid} but was already fixed")
                    
        # fix all network errors in log files
        miss_interfaces = self.meta_info['miss_interfaces']
        if len(miss_interfaces) > 0:
            logger.debug(f"Found {miss_interfaces} miss_interfaces network interface errors")
            res = {
                "category": "CREATE",
                "description": "CREATE_NETWORK",
                "syscalls": [""],
                "miss_interfaces": miss_interfaces,
                "fix_strategy": "create_network_device"
            }

            logger.debug(f"Consolidated network error: interfaces={res['miss_interfaces']}")
            

            if not self.is_strategy_enabled(res):
                logger.debug(f"Skipping network device creation due to disabled CREATE strategy")
                pass
            
            else:
                logger.debug(f"Returning network device creation error: {res}")
                return res
                    
                
        logger.debug(f"match files, ioctl error")
        # match files, ioctl error
        for pid in worklist:
            if pid not in self.process_info:
                logger.debug(f"Process {pid} not in process_info, skipping")
                continue
            
            if not self.process_info[pid]: # no syscalls
                continue
                
            logger.debug(f"Analyzing failures for process {pid}")
            candidate_errors = self._analyze_process_failures(pid)
            
            if isinstance(candidate_errors, list):
                logger.debug(f"Found {len(candidate_errors)} candidate errors for process {pid}")
                for error in candidate_errors:
                    if not self._is_error_fixed(error, self.fixed_errors):
                        # Check if similar error was fixed before with FILL_CONTENT or INFER_NVRAM
                        for fixed_error in self.fixed_errors:
                            if self._is_same_error(error, fixed_error, fixed_nvram_keys) and \
                               fixed_error.get("fix_strategy") in ["fill_file_content", "infer_nvram_value"]:
                                error["fix_strategy"] = "infer_magic_byte"
                                logger.debug(f"Changed fix strategy to infer_magic_byte for error: {error}")
                        logger.debug(f"Process {pid} found unfixed error: {error}")
                        return error
            elif candidate_errors:
                if not self._is_error_fixed(candidate_errors, self.fixed_errors):
                    # Check if similar error was fixed before with FILL_CONTENT or INFER_NVRAM
                    for fixed_error in self.fixed_errors:
                        if self._is_same_error(candidate_errors, fixed_error, fixed_nvram_keys) and \
                           fixed_error.get("fix_strategy") in ["fill_content", "infer_nvram_value"]:
                            candidate_errors["fix_strategy"] = "infer_magic_byte"
                            logger.debug(f"Changed fix strategy to infer_magic_byte for error: {candidate_errors}")
                    logger.debug(f"Process {pid} found unfixed error: {candidate_errors}")
                    return candidate_errors
            elif candidate_errors:
                logger.debug(f"Error found for process {pid} but was already fixed")
                
        
        logger.debug(f"match IPC error, socket error")
        if self.found_peer_process:
            # Match IPC errors (socket-based)
            for pid in worklist:
                syscalls = self.process_info[pid]['logs']
                candidate_errors = self._match_ipc_failures(syscalls)
                logger.debug(f"Found IPC error: {candidate_errors}")
                
                network_file_data = self._parse_firmwell_net_file()
                connect_fd_map = network_file_data.get('connect_fd', {})
                
                if candidate_errors and 'socket_fd' in candidate_errors:
                    socket_fd = candidate_errors['socket_fd']
                    if socket_fd in connect_fd_map:
                        logger.debug(f"socket_fd in connect_fd_map: {socket_fd}, {connect_fd_map[socket_fd]}")
                        addr = connect_fd_map[socket_fd]

                        if "ubus.sock" in addr:  # common case for ubus.sock - prefer ubusd if found
                            candidate_errors['peer_process_name'] = '/sbin/ubusd'
                            logger.debug("ubus.sock detected, using /sbin/ubusd as peer")
                        else:
                        
                            # Use dynamic peer process identification
                            peer_process = self._identify_peer_process(addr)
                            if peer_process:
                                candidate_errors['peer_process_name'] = peer_process
                                logger.debug(f"Dynamically identified peer process: {peer_process} for address: {addr}")
                            else:
                                candidate_errors = None
                    
                
                
                logger.debug(f"Found socket connection failure: {candidate_errors}")
                
                if candidate_errors and isinstance(candidate_errors, list):
                    logger.debug(f"Found {len(candidate_errors)} candidate errors for process {pid}")
                    for error in candidate_errors:
                        if not self._is_error_fixed(error, self.fixed_errors):
                            logger.debug(f"Process {pid} found unfixed error: {error}")
                            return error
                elif candidate_errors:
                    if not self._is_error_fixed(candidate_errors, self.fixed_errors):
                        logger.debug(f"Process {pid} found unfixed error: {candidate_errors}")
                        return candidate_errors
                elif candidate_errors:
                    logger.debug(f"Error found for process {pid} but was already fixed")

            # Match IPC errors (shared memory-based)
            for pid in worklist:
                if pid not in self.process_info:
                    continue
                syscalls = self.process_info[pid]['logs']
                candidate_errors = self._match_crash_after_shm_ipc(syscalls)
                if candidate_errors:
                    # Check if the process itself accesses a shm_id file before the
                    # failed shmat — this means the process manages its own shared
                    # memory segment and the peer is "self".
                    if self._has_shm_id_file_access_before_crash(syscalls):
                        peer_process = "self"
                        logger.debug("shm_id file access detected before shmat crash, peer is 'self'")
                    else:
                        # Dynamically identify peer process using shared memory
                        peer_process = self._identify_shm_peer_process()
                        if not peer_process:
                            peer_process = "self"
                            logger.warning("No peer process found for shared memory, using 'self' as fallback")
                        else:
                            logger.debug(f"Identified SHM peer process: {peer_process}")
                    candidate_errors['peer_process_name'] = peer_process

                    if not self._is_error_fixed(candidate_errors, self.fixed_errors):
                        logger.debug(f"Process {pid} found unfixed SHM IPC error: {candidate_errors}")
                        return candidate_errors

        logger.debug("No unfixed errors found.")
        return None
    
    def _find_error_process_worklist(self, root_pid: int) -> list:
        """Build a prioritized worklist of PIDs to analyze, starting from the root process.

        Performs DFS through the process tree, prioritizing segfaulted processes
        and those with non-zero exit codes.
        """
        worklist = []
        
        def dfs(pid: int):
            children = self.meta_info.get("parent_to_children", {}).get(pid, [])
            for child in reversed(children):
                if self.meta_info.get("process_map", {}).get(child, {}) == "/bin/sh":
                    continue
                dfs(child)
            worklist.append(pid)
        
        try:
            dfs(root_pid)
        except RecursionError:
            logger.error(f"Recursion error in DFS, returning initpid")
            return [root_pid]
        
        # Prioritize segfaulted processes
        for pid in worklist:
            if self.process_info.get(pid, {}).get("segfaulted", False):
                logger.debug(f"Found segfaulted process {pid}, returning it as sole item in worklist")
                return [pid]
        

        for pid in worklist:
            exit_code = self.process_info.get(pid, {}).get("exit_code", 0)
            if exit_code != 0:
                logger.debug(f"Found process {pid} with non-zero exit code {exit_code}, prioritizing it")
           
                worklist.remove(pid)
                return [pid] + worklist
        
        logger.debug(f"Final worklist: {worklist}")
        return worklist
    
    def _analyze_process_failures(self, pid):
        """Analyze a process's syscall history for file, ioctl, and IPC errors."""
        if pid not in self.process_info:
            logger.debug(f"Process {pid} not found in process_info")
            return []
        
        syscalls = self.process_info[pid]['logs']
        logger.debug(f"Analyzing process {pid} with {len(syscalls)} syscalls")
        
        if len(syscalls) == 0:
            logger.debug(f"No syscalls found for process {pid}")
            return []
        
        logger.debug(f"Checking for empty file reads")
        empty_file_error = self._match_empty_file_reads(syscalls)
        if empty_file_error:
            logger.debug(f"Found empty file read error: {empty_file_error}")
            return empty_file_error

        logger.debug(f"match crash after ioctl")
        crash_error = self._match_crash_after_ioctl(syscalls)
        if crash_error:
            logger.debug(f"Found crash after ioctl: {crash_error}")
            return crash_error
        
 
        logger.debug(f"Checking for individual syscall failures")
        for i, syscall in enumerate(syscalls[::-1]):
            if syscall.get("error"):
                last_failure = syscall
                syscall_name = last_failure["call"]
                args = last_failure["args"]
                error_msg = last_failure["error_msg"]
                
                # logger.debug(f"Analyzing failed syscall: {syscall_name}, error={error_msg}")
                
                error = None
                if syscall_name in ["open", "openat", "stat", "stat64", "access"]:
                    error = self._match_file_access_error(last_failure, syscalls)
                    
                    
                if error:
                    if error.get("fix_strategy") == "create_system_file" and self._is_error_fixed(error, self.fixed_errors):
                        error = {
                            "category": "INFER",
                            "description": "FILL_MAGIC",
                            "syscalls": error.get("syscalls", []),
                            "path": error.get("path", ""),
                            "fix_strategy": "fill_file_content",
                            "crash_pattern": []
                        }
                    if not self._is_error_fixed(error, self.fixed_errors) and self.is_strategy_enabled(error):
                        logger.debug(f"Found unfixed error from syscall {i}: {error}")
                        return error
                
        
        logger.debug(f"No errors found for process {pid}")
        return []
    
    
    def _match_nvram_error(self, syscalls):
        """Scan syscalls for NVRAM access errors and consolidate them into a single error pattern."""
        logger.debug(f"_match_nvram_error")
        
        if len(syscalls) == 0:
            logger.debug(f"No syscalls found for process ")
            return None
        
        nvram_errors = []
        
        for i, syscall in enumerate(syscalls[::-1]):
            if syscall.get("error"):
                last_failure = syscall
                syscall_name = last_failure["call"]
                args = last_failure["args"]
                error_msg = last_failure["error_msg"]
                
                # logger.debug(f"Analyzing failed syscall: {syscall_name}, error={error_msg}")
                
                if syscall_name in ["open", "openat", "stat", "stat64", "access"]:
                    error = self._match_nvram_access_error(last_failure)
                
                    if error and not self._is_error_fixed(error, self.fixed_errors):
                        logger.debug(f"Found unfixed error from syscall {i}: {error}")
                        nvram_errors.append(error)
                        
        
        # merge all nvram errors
        if nvram_errors:
            logger.debug(f"Found {len(nvram_errors)} nvram errors")
            res =  {
                "category": "INFER",
                "description": "INFER_NVRAM",
                "syscalls": [],
                "miss_nvrams": set(),
                "fix_strategy": "infer_nvram_value"
            }
            for i in nvram_errors:
                res['syscalls'].append(i['syscalls'])
                res['miss_nvrams'].update(i['miss_nvrams'])
            
            if self.is_strategy_enabled(res):
                logger.debug(f"Consolidated nvram error: nvrams={res['miss_nvrams']}")
                return res
        
        return None
    
    def _match_network_interfaces_error(self, syscalls):
        """Scan syscalls for network interface errors and consolidate them."""
        network_errors = []
        
        if len(syscalls) == 0:
            logger.debug(f"No syscalls found for process")
            return []
        
        for syscall in syscalls[::-1]:
            if syscall["error"]:
                res = self._match_network_error(syscall)
                if res:
                    logger.debug(f"Found network error in syscall: {res}")
                    network_errors.append(res)

        if network_errors:
            logger.debug(f"Found {len(network_errors)} network interface errors")
            res = {
                "category": "CREATE",
                "description": "CREATE_NETWORK",
                "syscalls": [syscall['original_syscall']],
                "miss_interfaces": set(),
                "fix_strategy": "create_network_device"
            }
            for i in network_errors:
                res['syscalls'].append(i['syscalls'])
                res['miss_interfaces'].update(i['miss_interfaces'])

            logger.debug(f"Consolidated network error: interfaces={res['miss_interfaces']}")
            

            if not self.is_strategy_enabled(res):
                logger.debug(f"Skipping network device creation due to disabled CREATE strategy")
                return None
                
            return res
        
        return None
    
    def _match_network_error(self, syscall):
        """Match network-related errors (Cannot assign requested address, No such device)."""
        syscall_name = syscall["call"]
        args = syscall["args"]
        error_msg = syscall.get("error_msg", "")
        
        # Parse FIRMWELL_NET file for additional network error information
        network_file_data = self._parse_firmwell_net_file()
        fd_device_map = network_file_data.get('fd_device', {})
        fd_ip_port_map = network_file_data.get('fd_ip_port', {})
        

        # Extract socket fd if available
        socket_fd = None
        try:
            socket_fd = int(args[0])
        except Exception:
            pass
        
        device_name = None


        
        if syscall_name == "setsockopt" and ("SO_BINDTODEVICE" in str(args) or "No such device" in error_msg):
            # Extract device name from the setsockopt args if available
            try:
                # The device name may be in args[3]
                device_arg = str(args[3]).strip('"')
                if device_arg and not device_name:
                    device_name = device_arg
            except Exception as e:
                logger.debug(f"_match_network_error: {e}")

            if 'device' in syscall:
                device = syscall['device']
                logger.debug(f"setsockopt dev: {device}")
            else:
                device = fd_device_map[socket_fd]
                
            miss_interfaces = set()
            if device_name:
                miss_interfaces.add(device)
                
            return {
                "category": "CREATE",
                "description": "CREATE_NETWORK",
                "syscalls": [syscall['original_syscall']],
                "miss_interfaces": miss_interfaces or None,
                "ip_address": None,
                "socket_fd": socket_fd,
                "device": device_name,  # Add device specifically for setsockopt errors
                "fix_strategy": "create_network_device"
            }
        
        if self.enable_enhance_create:
            if syscall_name == "ioctl" and "No such device" in error_msg and "SIO" in str(args): # SIO*
                # Extract device name from ioctl if available in our parsed data
                if not device_name:
                    try:
                        device_name = syscall['device']
                        logger.debug(f"ioctl dev: {device_name}")
                    except Exception as e:
                        logger.debug(f"_match_network_error: {e}")
                        
                miss_interfaces = set()
                if device_name:
                    miss_interfaces.add(device_name)
                    
                return {
                    "category": "CREATE",
                    "description": "CREATE_NETWORK",
                    "syscalls": [syscall['original_syscall']],
                    "miss_interfaces": miss_interfaces,
                    "ip_address": None,
                    "socket_fd": socket_fd,
                    "device": device_name,
                    "fix_strategy": "create_network_device"
                }
            
        requested_ip = None
        if syscall_name in ["bind", "setsockopt", "ioctl"] and "Cannot assign requested address" in error_msg:
            if syscall_name not in ['ioctl'] and self.enable_enhance_create:
                try:
                    if syscall_name == "bind" or syscall_name == "setsockopt":
                        socket_fd = int(args[0])
                        # Extract IP address from bind arguments
                        bind_args = str(args[1]) if len(args) > 1 else ""
                        ip_match = re.search(r'inet_addr\("([^"]+)"\)', bind_args)
                        if ip_match:
                            requested_ip = ip_match.group(1)
                    elif syscall_name == "ioctl":
                        socket_fd = int(args[0])
                        # Get device name and IP from FIRMWELL_NET file based on socket fd
                        device_name = fd_device_map.get(socket_fd)
                        ip_address, port = fd_ip_port_map.get(socket_fd)
                        if fd_ip_port_map and socket_fd in fd_ip_port_map and len(fd_ip_port_map[socket_fd]) > 0:
                            requested_ip = fd_ip_port_map[socket_fd][0]
    
                        
                except Exception as e:
                    logger.debug(f"_match_network_error: {e}")
                
                # Look up the device name associated with this socket fd
                device_name = fd_device_map.get(socket_fd)
                
                if device_name:
                    miss_interfaces = set()
                    miss_interfaces.add(device_name)
                    
                    return {
                        "category": "CREATE",
                        "description": "CREATE_NETWORK",
                        "syscalls": [syscall['original_syscall']],
                        "miss_interfaces": miss_interfaces,
                        "ip_address": requested_ip,
                        "socket_fd": socket_fd,
                        "fix_strategy": "create_network_device"
                    }
        
        return None

    def _parse_firmwell_net_file(self):
        """Parse the FIRMWELL_NET file to extract network error information."""
        result = {
            'fd_device': {},  # maps socket fd to device name
            'fd_ip_port': {}  # maps socket fd to (ip, port) tuple
        }
        
        if not self.env:
            logger.debug("No environment available to read FIRMWELL_NET file")
            return result
            
        try:
            firmwell_net_content = self.env.read_file("FIRMWELL_NET")
            if not firmwell_net_content:
                # logger.debug("FIRMWELL_NET file is empty or does not exist")
                return result
                
            for line in firmwell_net_content.splitlines():
                line = line.strip()
                
                # Parse [FD-DEVICE] entries (socket fd to device mapping)
                if line.startswith("[FD-DEVICE] :"):
                    try:
                        data = line.replace("[FD-DEVICE] :", "").strip()
                        fd, device = data.split(":", 1)
                        result['fd_device'][int(fd)] = device
                        # logger.debug(f"Found FD-DEVICE mapping: {fd} -> {device}")
                    except Exception as e:
                        logger.warning(f"Failed to parse FD-DEVICE line: {line}, error: {e}")
                
                # Parse [FD-IP-PORT] entries (socket fd to IP:port mapping)
                elif line.startswith("[FD-IP-PORT] :"):
                    try:
                        data = line.replace("[FD-IP-PORT] :", "").strip()
                        parts = data.split(":")
                        if len(parts) >= 3:
                            fd = int(parts[0])
                            ip = parts[1]
                            port = parts[2]
                            result['fd_ip_port'][fd] = (ip, port)
                            # logger.debug(f"Found FD-IP-PORT mapping: {fd} -> {ip}:{port}")
                    except Exception as e:
                        logger.warning(f"Failed to parse FD-IP-PORT line: {line}, error: {e}")
                
                # Parse [CONNECT-FD-UNIX] entries (socket fd to Unix socket path mapping)
                elif line.startswith("[CONNECT-FD-UNIX] :"):
                    try:
                        data = line.replace("[CONNECT-FD-UNIX] :", "").strip()
                        fd, path = data.split(":", 1)
                        if 'connect_fd' not in result:
                            result['connect_fd'] = {}
                        result['connect_fd'][int(fd)] = path.strip()
                        # logger.debug(f"Found CONNECT-FD-UNIX mapping: {fd} -> {path}")
                    except Exception as e:
                        logger.warning(f"Failed to parse CONNECT-FD-UNIX line: {line}, error: {e}")
                        
                # Parse [IOCTL] entries (ioctl command, fd, interface name, and IP)
                elif line.startswith("[IOCTL]"):
                    try:
                        data = line.replace("[IOCTL]", "").strip()
                        # Split by spaces to get individual parameters
                        params = {}
                        for param in data.split():
                            if '=' in param:
                                key, value = param.split('=', 1)
                                params[key] = value
                        
                        # Extract relevant information
                        fd = int(params.get('fd', 0))
                        ifname = params.get('ifname', '')
                        ip = params.get('ip', '')
                        
                        # Store in result dictionary
                        if 'ioctl_info' not in result:
                            result['ioctl_info'] = {}
                        
                        if fd not in result['ioctl_info']:
                            result['ioctl_info'][fd] = {
                                'ifname': ifname,
                                'ip': ip,
                                'cmds': []
                            }
                        
                        # Add command to the list
                        cmd = params.get('cmd', '')
                        if cmd:
                            result['ioctl_info'][fd]['cmds'].append(cmd)
                            
                        # logger.debug(f"Found IOCTL entry: fd={fd}, ifname={ifname}, ip={ip}")
                    except Exception as e:
                        logger.warning(f"Failed to parse IOCTL line: {line}, error: {e}")
                
                # # Parse [BIND_DEVICE] entries directly (device name)
                # elif line.startswith("[BIND_DEVICE]"):
                #     try:
                #         device = line.replace("[BIND_DEVICE]", "").strip()
                #         if device:
                #             # Store in a special entry that doesn't require a socket fd
                #             if 'devices' not in result:
                #                 result['devices'] = set()
                #             result['devices'].add(device)
                #             logger.debug(f"Found BIND_DEVICE entry: {device}")
                #     except Exception as e:
                #         logger.warning(f"Failed to parse BIND_DEVICE line: {line}, error: {e}")
                #
                # # Parse [IP-PORT] entries directly (IP:port pairs)
                # elif line.startswith("[IP-PORT] :"):
                #     try:
                #         data = line.replace("[IP-PORT] :", "").strip()
                #         parts = data.split(":")
                #         if len(parts) >= 2:
                #             ip = parts[0]
                #             port = parts[1]
                #             if 'ip_ports' not in result:
                #                 result['ip_ports'] = []
                #             result['ip_ports'].append((ip, port))
                #             logger.debug(f"Found IP-PORT entry: {ip}:{port}")
                #     except Exception as e:
                #         logger.warning(f"Failed to parse IP-PORT line: {line}, error: {e}")
        
        except Exception as e:
            logger.error(f"Error parsing FIRMWELL_NET file: {e}")
        
        return result
    
    def _match_crash_after_ioctl(self, syscalls):
        """Detect ioctl errors in the last few syscalls that may need content inference."""
        for i in range(len(syscalls) - 1, max(0, len(syscalls) - 10), -1):
            # 23 ioctl(4,0x89f2,0x2b2aa110) = -1 errno=25 (Inappropriate ioctl for device)
            syscall = syscalls[i]
            name = syscall.get("call")
            args = syscall.get("args", [])
            if name == "ioctl" and syscall.get("error") and not isinstance(args[1], str): # TCGETS, TIOCNOTTY, etc
                    # and "TCGETS" not in str(args)):
                error = {
                    "category": "INFER",
                    "description": "INFER_CONTENT",
                    "syscalls": [syscall['original_syscall']],
                    "fix_strategy": "fill_ioctl_content",
                    "op": args[1], # int
                }
                if self.is_strategy_enabled(error):
                    return error
        return None

    def _match_nvram_access_error(self, syscall):
        """Match NVRAM file access errors from a failed syscall."""
        syscall_name = syscall["call"]
        args = syscall["args"]
        error_msg = syscall["error_msg"]
        
        file_path = None
        if syscall_name == "open":
            file_path = args[0].strip('"')
        elif syscall_name == "openat":
            file_path = args[1].strip('"')
        elif syscall_name in ["stat", "stat64", "access"]:
            file_path = args[0].strip('"')
        
        if not file_path:
            logger.debug(f"No file path found in syscall {syscall_name}")
            return None
        
        logger.debug(f"Matching nvram error for path: {file_path}, syscall={syscall_name}")
        
        if syscall_name.startswith("open") and (os.path.basename(file_path) == "" or file_path.endswith('/')):
            logger.debug(f"Not treating as error: syscall {syscall_name} targets a directory")
            return None
        
        file_name = os.path.basename(file_path)
        ext = file_name.split(".")[-1]
        if ext not in WEB_EXTS and file_name in [os.path.basename(i) for i in self.meta_info.get('accessed_files', [])]:
            logger.debug(f"File {file_name} already in accessed_files list, skipping")
            return None
        
        
        if file_path.startswith(IGNORE_PATH):
            logger.debug(f"Path {file_path} in IGNORE_PATH, skipping")
            return None
        
        if "gh_nvram" in file_path.lower():
            logger.debug(f"Found NVRAM file access: {file_path}")
            return {
                "category": "INFER",
                "description": "INFER_NVRAM",
                "syscalls": [syscall['original_syscall']],
                "miss_nvrams": {file_path},
                "fix_strategy": "infer_nvram_value"
            }
        
        logger.debug(f"No specific error pattern matched for {file_path}")
        return None
    
    def _match_file_access_error(self, syscall, syscalls):
        """Match file access errors and determine the appropriate fix strategy (reuse, create, infer)."""
        syscall_name = syscall["call"]
        args = syscall["args"]
        error_msg = syscall["error_msg"]
        
        file_path = None
        if syscall_name == "open":
            file_path = args[0].strip('"')
        elif syscall_name == "openat":
            file_path = args[1].strip('"')
        elif syscall_name in ["stat", "stat64", "access"]:
            file_path = args[0].strip('"')
        
        if not file_path:
            logger.debug(f"No file path found in syscall {syscall_name}")
            return None
            
        logger.debug(f"Matching file access error for path: {file_path}, syscall={syscall_name}")
        
        if syscall_name.startswith("open") and (os.path.basename(file_path) == "" or file_path.endswith('/')):
            logger.debug(f"Not treating as error: syscall {syscall_name} targets a directory")
            return None
        
        file_name = os.path.basename(file_path)
        ext = file_name.split(".")[-1]
        if ext not in WEB_EXTS and file_name in [os.path.basename(i) for i in self.meta_info.get('accessed_files', [])]:
            # logger.debug(f"File {file_name} already in accessed_files list, skipping")
            return None
        
        template_dir = "/fw/firmwell/greenhouse_files/templates/"
        template_matches = []
        
        if os.path.exists(template_dir):
            current_file_name = os.path.basename(file_path)
            template_files = os.listdir(template_dir)
            
            if current_file_name in template_files:
                for other_syscall in syscalls:
                    other_syscall_name = other_syscall.get('call', '')
                    if not other_syscall_name.startswith(('open', 'stat', 'access')):
                        continue
                        
                    # Extract file path from syscall args
                    other_file_path = None
                    if other_syscall_name == "open":
                        other_file_path = other_syscall.get('args', [])[0].strip('"')
                    elif other_syscall_name == "openat":
                        other_file_path = other_syscall.get('args', [])[1].strip('"')
                    elif other_syscall_name in ["stat", "stat64", "access"]:
                        other_file_path = other_syscall.get('args', [])[0].strip('"')
                        
                    if not other_file_path:
                        continue
                        
                    other_file_name = os.path.basename(other_file_path)
                    if other_file_name in template_files:
                        template_matches.append({
                            "syscall": other_syscall['original_syscall'],
                            "path": other_file_path,
                            "file_path": os.path.join(template_dir, other_file_name)
                        })
                
                if template_matches:
                    logger.debug(f"Found {len(template_matches)} template file matches")
                    error = {
                        "category": "REUSE",
                        "description": "reuse_template",
                        "syscalls": [match["syscall"] for match in template_matches],
                        "paths": [match["path"] for match in template_matches],
                        "file_paths": [match["file_path"] for match in template_matches],
                        "fix_strategy": "reuse_file"
                    }
                    if self.is_strategy_enabled(error):
                        return error
                    
        if not os.path.exists(file_path):
            found, new_cwd = self.check_cwd(self.fs_path, [file_path], self.cwd)
            if found:
                logger.debug(f"CWD error detected for file {file_path}, new_cwd={new_cwd}")
                error = {
                    "category": "REUSE",
                    "description": "reuse_cwd",
                    "syscalls": [syscall['original_syscall']],
                    "path": file_path,
                    "fix_strategy": "reuse_file",
                    "cwd": new_cwd
                }
                if self.is_strategy_enabled(error):
                    return error
                # continue

        if "www.satellite" in file_path.lower():
            logger.debug(f"Found www.satellite in path: {file_path}")
            error = {
                "category": "REUSE",
                "description": "reuse_directory",
                "syscalls": [syscall['original_syscall']],
                "path": file_path,
                "fix_strategy": "reuse_file"
            }
            if self.is_strategy_enabled(error):
                return error
            # continue
        
        if ((file_path.endswith('.html') and file_name.replace(".html", "htm") in [os.path.basename(i) for i in
                                                                                   self.meta_info.get('accessed_files',
                                                                                                      [])]) or
                (file_path.endswith('.htm') and file_name.replace(".htm", "html") in [os.path.basename(i) for i in
                                                                                      self.meta_info.get(
                                                                                          'accessed_files', [])])):
            logger.debug(f"Skipping HTML/HTM file with alternative extension already accessed: {file_name}")
            return None
        
        if not file_path.startswith(("/proc", "/sys", "/dev")) and "bin/" not in file_path and "gh_nvram" not in file_path:
            sourcefiles = find_files(os.path.basename(file_path), self.fs_path, include_backups=True, skip=[])
            if sourcefiles:
                source_file = sourcefiles[0]
                logger.debug(f"Found source file to reuse: {source_file}")
                if self.fs_path in source_file:
                    error = {
                        "category": "REUSE",
                        "description": "reuse_file",
                        "syscalls": [syscall['original_syscall']],
                        "path": file_path,
                        "file_path": source_file.replace(self.fs_path, ""),
                        "fix_strategy": "reuse_file"
                    }
                    if self.is_strategy_enabled(error):
                        return error
        if syscall_name == "access" and "F_OK" in str(args):
            try:
                current_index = syscalls.index(syscall)
                if current_index + 1 < len(syscalls) and syscalls[current_index + 1]["call"] == "exit" and syscalls[current_index + 1]["args"][0] == "0":

                    logger.debug(f"Detected config state check pattern: {file_path} followed by exit(0)")
                    error = {
                        "category": "CREATE",
                        "description": "CREATE_SYSFILE", 
                        "syscalls": [syscall['original_syscall']],
                        "path": file_path,
                        "fix_strategy": "create_system_file"
                    }
                    if self.is_strategy_enabled(error):
                        return error
                    
            except (ValueError, IndexError) as e:
                logger.debug(f"Error checking syscall sequence: {e}")
                

        if file_path.startswith(IGNORE_PATH):
            logger.debug(f"Path {file_path} in IGNORE_PATH, skipping")
            return None

        if file_path.startswith("/lib") and file_path.endswith(".so"):
            logger.debug(f"Found .so file access error: {file_path}")
 
            sourcefiles = find_files(os.path.basename(file_path), self.fs_path, include_backups=True, skip=[])
            if sourcefiles:
                source_file = sourcefiles[0]
                source_dir = os.path.dirname(source_file)
                logger.debug(f"Found source directory for .so files: {source_dir}")
                
   
                so_files = []
                for root, _, files in os.walk(source_dir):
                    for file in files:
                        if file.endswith(".so"):
                            so_files.append(os.path.join(root, file))
                
                if so_files:
                    logger.debug(f"Found {len(so_files)} .so files in source directory")
                    error = {
                        "category": "REUSE",
                        "description": "reuse_so_files",
                        "syscalls": [syscall['original_syscall']],
                        "path": file_path,
                        "source_dir": source_dir.replace(self.fs_path, ""),
                        "target_dir": os.path.dirname(file_path),
                        "fix_strategy": "reuse_file"
                    }
                    if self.is_strategy_enabled(error):
                        return error
        
        # 
        if file_path.startswith(("/proc", "/sys", "/dev")):
            # 
            pattern = r'^/proc/(\d+)/stat$'
            match = re.match(pattern, file_path)
            if match is not None:
                logger.debug(f"Skipping process stat file: {file_path}")
                return None
                
            pattern = r'^/proc/(\d+)/cmdline$'
            match = re.match(pattern, file_path)
            if match is not None:
                logger.debug(f"Skipping process cmdline file: {file_path}")
                return None
                
            pattern = r'^/proc/(\d+)$'
            match = re.match(pattern, file_path)
            if match is not None:
                logger.debug(f"Skipping process directory: {file_path}")
                return None
            
        
            logger.debug(f"Found system file access error: {file_path}")
            error = {
                "category": "CREATE",
                "description": "CREATE_SYSFILE",
                "syscalls": [syscall['original_syscall']],
                "path": file_path,
                "fix_strategy": "create_system_file"
            }
            if self.is_strategy_enabled(error):
                return error

        # Check for nvram errors across all syscalls
        # # NVRAM
        # if "gh_nvram" in file_path.lower():
        #     logger.debug(f"Found NVRAM file access: {file_path}")
        #     return {
        #         "category": "INFER",
        #         "description": "INFER_NVRAM",
        #         "syscalls": [syscall['original_syscall']],
        #         "miss_nvrams": {file_path},
        #         "fix_strategy": "infer_nvram_value"
        #     }
        #        candidate_errors = self._match_nvram_error(syscalls)
        candidate_errors = self._match_nvram_error(syscalls)
        if candidate_errors:
            if self.is_strategy_enabled(candidate_errors):
                return candidate_errors
        
        logger.debug(f"No specific error pattern matched for {file_path}")
        return None
    
    def _match_crash_after_shm_ipc(self, syscalls):
        """Detect crashes caused by shared memory IPC failures (e.g. SHMAT, SHMGET).

        Args:
            syscalls: List of parsed syscall events.

        Returns:
            dict: Error pattern if a shared memory crash is found, or None.
        """
        logger.debug(f"Checking for crashes after shared memory operations")
        
        # Find the crash point
        crash_index = -1
        for i, syscall in enumerate(syscalls):
            if syscall.get("call") == "SIGSEGV" or syscall.get("is_signal", False) or "SIGSEGV" in str(
                    syscall.get("details", "")):
                crash_index = i
                break
                
        if crash_index <= 0:
            logger.debug("No crash found in syscalls")
            return None
            
        # IPC call type codes
        IPC_TYPES = {
            21: "SHMAT",
            22: "SHMDT", 
            23: "SHMGET",
            24: "SHMCTL",
        }
        
        for i in range(crash_index - 1, max(0, crash_index - 20), -1):
            syscall = syscalls[i]
            syscall_name = syscall.get("call")
            args = syscall.get("args", [])
            errno = syscall.get("errno", None)
            
            # Check for shmat failures
            if syscall_name == "shmat":
                if args and len(args) >= 1 and args[0] == "-1" and errno == 22:
                    description = f"(SHMAT): error"
                    logger.debug(f"Detected invalid SHMAT error: {description}")

                    error = {
                        "category": "FIX-IN-PEER",
                        "description": "FIX_IN_PEER_IPC",
                        "syscalls": [{
                            "name": syscall_name,
                            "args": args,
                            "error_code": errno,
                            "ipc_type": "SHMAT",
                            "ipc_id": -1,
                            "is_crash": True
                        }],
                        "peer_process_name": None,
                        "ipc_type": "SHMAT",
                        "ipc_id": -1,
                        "fix_strategy": "fix_shared_memory"
                    }
                    if self.is_strategy_enabled(error):
                        return error
                    
            if syscall_name == "ipc" and args and len(args) >= 2:
                try:
                    ipc_call_type = int(args[0])
                    ipc_call_name = IPC_TYPES.get(ipc_call_type, "UNKNOWN")
                    ipc_id = args[1] if len(args) > 1 else None
                    
                    logger.debug(f"IPC call type: {ipc_call_type} ({ipc_call_name}), ID: {ipc_id}")
                    
                    if ipc_call_name in ["SHMGET", "SHMAT", "SHMCTL"]:
                        if ipc_call_name == "SHMGET":
                            description = f"Shared memory error (SHMGET): ID={ipc_id}, errno={errno}"
                        elif ipc_call_name == "SHMAT":
                            description = f"Shared memory error (SHMAT): ID={ipc_id}, errno={errno}"
                        else:
                            description = f"Shared memory error (SHMCTL): ID={ipc_id}, errno={errno}"

                        logger.debug(f"Detected IPC error: {description}")

                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": [{
                                "name": syscall_name,
                                "args": args,
                                "error_code": errno,
                                "ipc_type": ipc_call_name,
                                "ipc_id": ipc_id
                            }],
                            "peer_process_name": None,
                            "ipc_type": ipc_call_name,
                            "ipc_id": ipc_id,
                            "fix_strategy": "fix_shared_memory"
                        }
                        if self.is_strategy_enabled(error):
                            return error
                except (ValueError, IndexError) as e:
                    logger.warning(f"IPC root: {e}")
        
        logger.debug("No shared memory related crashes found")
        return None
    

    
    def _match_crash_after_file_ops(self, syscalls):
        """Detect crashes that follow file open/read/close sequences, suggesting missing file content.

        Args:
            syscalls: List of parsed syscall events.

        Returns:
            dict: Error pattern if a crash after file ops is found, or None.
        """
        crash_index = -1
        for i, syscall in enumerate(syscalls):
            if syscall.get("call") == "SIGSEGV" or syscall.get("is_signal", False) or "SIGSEGV" in str(
                    syscall.get("details", "")):
                crash_index = i
                break
        
        if crash_index <= 0:
            return None
        
        from collections import defaultdict
        fd_operations = defaultdict(list)
        open_files = {}
        
        open_analyzed = False
        for i in range(crash_index - 1, max(0, crash_index - 20), -1):
            syscall = syscalls[i]
            name = syscall.get("call")
            args = syscall.get("args", [])
            retval = syscall.get("retval", 0)
            error = syscall.get("error", False)
            
            if open_analyzed:
                break
            
            if name == "close" and not error and len(args) >= 1:
                try:
                    fd = int(args[0])
                    fd_operations[fd].append(("close", None, None, i, syscall))
                except (ValueError, IndexError):
                    pass
            elif name == "read" and not error and len(args) >= 1:
                try:
                    fd = int(args[0])
                    size = retval if isinstance(retval, int) else 0
                    fd_operations[fd].append(("read", None, size, i, syscall))
                except (ValueError, IndexError):
                    pass
            elif (name == "open" or name == "openat"):
                open_analyzed = True
                if not error and isinstance(retval, int) and retval >= 0:
                    try:
                        fd = retval
                        path = syscall.get("file", "")
                        if path:
                            if fd not in open_files:
                                open_files[fd] = path
                            fd_operations[fd].append(("open", path, fd, i, syscall))
                    except Exception:
                        pass
        
        for fd, ops in fd_operations.items():
            path = open_files.get(fd)
            if path:
                updated_ops = []
                for op_type, _, size, idx, syscall_obj in ops:
                    updated_ops.append((op_type, path, size, idx, syscall_obj))
                fd_operations[fd] = updated_ops
        
        for fd, operations in fd_operations.items():
            if fd not in open_files:
                continue
            path = open_files[fd]
            operations.sort(key=lambda x: x[3])
            if operations and operations[0][0] == "open":
                has_read = False
                for op in operations[1:]:
                    if op[0] == "read":
                        has_read = True
                        break
                if has_read:
                    related_syscalls = []
                    for op in operations:
                        syscall_obj = op[4]
                        related_syscalls.append({
                            "name": syscall_obj.get("call", ""),
                            "args": syscall_obj.get("args", []),
                            "error_code": None
                        })
                    if path.startswith(IGNORE_PATH):
                        continue
                    
                    if path and "/gh_nvram" in path.lower():
                        error = {
                            "category": "INFER",
                            "description": "INFER_NVRAM",
                            "syscalls": related_syscalls,
                            "path": path,
                            "fix_strategy": "infer_nvram_value",
                            "crash_pattern": operations
                        }
                        if self.is_strategy_enabled(error):
                            return error
                    error = {
                        "category": "INFER",
                        "description": "INFER_MAGIC",
                        "syscalls": related_syscalls,
                        "path": path,
                        # "fix_strategy": "infer_magic_bytes",
                        "fix_strategy": "fill_file_content",  # will escalate to infer on retry
                        "crash_pattern": operations
                    }
                    if self.is_strategy_enabled(error):
                        return error
        
        return None
    
    def _match_ipc_failures(self, syscalls):
        """Detect IPC failures: socket connect timeouts, incomplete recv, connection refused, etc."""
        socket_ops = defaultdict(list)
        
        for i, syscall in enumerate(syscalls):
            name = syscall.get("call")
            args = syscall.get("args", [])
            retval = syscall.get("retval")
            error = syscall.get("error", False)
            error_msg = syscall.get("error_msg", "")
            
            # Track socket operations by file descriptor
            if name == "socket" and not error and isinstance(retval, int) and retval >= 0:
                fd = retval
                socket_family = "UNKNOWN"
                if args and len(args) > 0:
                    socket_family = args[0]
                socket_ops[fd].append({
                    "op": "socket",
                    "family": socket_family,
                    "success": True,
                    "index": i,
                    "syscall": syscall
                })
            elif name == "connect" and len(args) > 0:
                try:
                    fd = int(args[0])
                    success = not error
                    socket_ops[fd].append({
                        "op": "connect",
                        "success": success,
                        "error_msg": error_msg,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass
            elif name == "send" and len(args) > 0:
                try:
                    fd = int(args[0])
                    success = not error
                    socket_ops[fd].append({
                        "op": "send",
                        "success": success,
                        "error_msg": error_msg,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass
            elif name == "recv" and len(args) > 0:
                try:
                    fd = int(args[0])
                    is_incomplete = syscall.get("incomplete", False)
                    socket_ops[fd].append({
                        "op": "recv",
                        "success": not error,
                        "error_msg": error_msg,
                        "incomplete": is_incomplete,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass
            elif name == "_newselect" and len(args) > 0:
                try:
                    fd = None
                    for arg in args[:2]:
                        arg = arg.strip()
                        if '[' in arg and ']' in arg:
                            # Extract number from [5] format
                            fd_match = re.search(r'\[(\d+)\]', arg)
                            if fd_match:
                                fd = fd_match.group(1)
                                fd = int(fd)
                                break
                    if fd:
                        is_incomplete = syscall.get("incomplete", False)
                        success = not error
                        retval_zero = retval == 0  # timeout (returned 0)
                        socket_ops[fd].append({
                            "op": "_newselect",
                            "success": success,
                            "error_msg": error_msg,
                            "incomplete": is_incomplete,
                            "retval_zero": retval_zero,
                            "index": i,
                            "syscall": syscall
                        })
                except (ValueError, IndexError):
                    pass
            elif name == "recvfrom" and len(args) > 0:
                try:
                    fd = int(args[0])
                    success = not error
                    socket_ops[fd].append({
                        "op": "recvfrom",
                        "success": success,
                        "error_msg": error_msg,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass
            elif name == "sendto" and len(args) > 0:
                try:
                    fd = int(args[0])
                    socket_ops[fd].append({
                        "op": "sendto",
                        "success": not error,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass
            elif name == "read" and len(args) > 0:
                try:
                    fd = int(args[0])
                    size = retval if isinstance(retval, int) else None
                    # Track reads on socket fds (size 0 may indicate peer disconnection)
                    socket_ops[fd].append({
                        "op": "read",
                        "success": not error,
                        "size": size,
                        "error_msg": error_msg,
                        "index": i,
                        "syscall": syscall
                    })
                except (ValueError, IndexError):
                    pass

        # Check for incomplete recv after successful connect/send
        for fd, operations in socket_ops.items():
            operations.sort(key=lambda x: x["index"])
            socket_op_list = [op for op in operations if op["op"] == "socket"]
            if not socket_op_list:
                continue
            
            socket_family = socket_op_list[0]["family"]
            
            """_summary_

            2665 socket(PF_UNIX,SOCK_STREAM,IPPROTO_IP) = 5
    2665 connect(5,0x2b2ab938,110) = 0
    2665 _newselect([],[5],[],{tv_sec = 60,tv_usec = 0}) =  = 0x00000001 ([],[5],[],{tv_sec = 59,tv_usec = 999998})
    2665 setsockopt(5,65535,4101,0x2b2ab928,0x8) = 0
    2665 send(5,724220544,648,0,0,0) = 648
    2665 _newselect([5],[],[],{tv_sec = 60,tv_usec = 0}) =  = 0x00000000 ([],[],[],{tv_sec = 0,tv_usec = 0})
    2665 _newselect([5],[],[],{tv_sec = 60,tv_usec = 0}) =  = 0x00000000 ([],[],[],{tv_sec = 0,tv_usec = 0})
    2665 _newselect([5],[],[],{tv_sec = 60,tv_usec = 0}) =  = 0x00000000 ([],[],[],{tv_sec = 0,tv_usec = 0})
    2665 shutdown(5,2,0,0,0,0) = 0
    2665 close(5) = 0
    2665 write(2,0x47e0cc,29) = 29
    2665 write(2,0x45aa40,5) = 5
    2665 write(2,0x45b9a8,1) = 1
    2665 write(2,0x2b2abb98,3) = 3
    2665 write(2,0x45b9ab,3) = 3
    2665 write(2,0x45aabc,16) = 16
    2665 write(2,0x2b6a0900,2) = 2
    2665 write(2,0x2b2abb1c,7) = 7
    2665 write(2,0x2b6a090a,1) = 1
    2665 exit(1)
            """
            # Check for consecutive _newselect timeouts
            newselect_ops = [op for op in operations if op["op"] == "_newselect"]
            consecutive_timeouts = 0
            for op in newselect_ops:
                if op.get("retval_zero", False):
                    consecutive_timeouts += 1
                else:
                    consecutive_timeouts = 0
                
                if consecutive_timeouts >= 3:  
                    # connect
                    prev_ops = [o for o in operations if o["index"] < op["index"]]
                    has_connect = any(p["op"] == "connect" and p["success"] for p in prev_ops)
                    
                    if has_connect:
                        related_syscalls = []
                        for prev_op in prev_ops:
                            if prev_op["op"] in ["socket", "connect", "send"]:
                                related_syscalls.append({
                                    "name": prev_op["syscall"].get("call", ""),
                                    "args": prev_op["syscall"].get("args", []),
                                    "error_code": None
                                })
                        # _newselect
                        related_syscalls.append({
                            "name": op["syscall"].get("call", ""),
                            "args": op["syscall"].get("args", []),
                            "error_code": None
                        })
                        
                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": related_syscalls,
                            "socket_fd": fd,
                            "socket_family": socket_family,
                            "fix_strategy": "fix_ipc_socket_service",
                            "consecutive_timeouts": True
                        }
                        if self.is_strategy_enabled(error):
                            return error
            
            # First check for incomplete recv
            for i, op in enumerate(operations):
                if op["op"] == "recv" and op.get("incomplete", False):
                    prev_ops = operations[:i]
                    has_connect = any(p["op"] == "connect" and p["success"] for p in prev_ops)
                    
                    if has_connect:
                        related_syscalls = []
                        for prev_op in prev_ops:
                            if prev_op["op"] in ["socket", "connect", "send"]:
                                related_syscalls.append({
                                    "name": prev_op["syscall"].get("call", ""),
                                    "args": prev_op["syscall"].get("args", []),
                                    "error_code": None
                                })
                        related_syscalls.append({
                            "name": op["syscall"].get("call", ""),
                            "args": op["syscall"].get("args", []),
                            "error_code": None
                        })
                        
                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": related_syscalls,
                            "socket_fd": fd,
                            "socket_family": socket_family,
                            "fix_strategy": "fix_ipc_socket_service",
                            "incomplete_recv": True
                        }
                        if self.is_strategy_enabled(error):
                            return error
                        
            # Check for incomplete _newselect
            for i, op in enumerate(operations):
                if op["op"] == "_newselect" and op.get("incomplete", False):
                    prev_ops = operations[:i]
                    has_connect = any(p["op"] == "connect" and p["success"] for p in prev_ops)
                    
                    if has_connect:
                        related_syscalls = []
                        for prev_op in prev_ops:
                            if prev_op["op"] in ["socket", "connect", "send"]:
                                related_syscalls.append({
                                    "name": prev_op["syscall"].get("call", ""),
                                    "args": prev_op["syscall"].get("args", []),
                                    "error_code": None
                                })
                        related_syscalls.append({
                            "name": op["syscall"].get("call", ""),
                            "args": op["syscall"].get("args", []),
                            "error_code": None
                        })
                        
                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": related_syscalls,
                            "socket_fd": fd,
                            "socket_family": socket_family,
                            "fix_strategy": "fix_ipc_socket_service",
                            "incomplete_newselect": True
                        }
                        if self.is_strategy_enabled(error):
                            return error
            """
              '3006 dup2(4,0) = 0',
  '3006 dup2(4,1) = 1',
  '3006 socket(PF_UNIX,SOCK_STREAM,IPPROTO_IP) = 5',
  '3006 connect(5,0x2b2ab318,110)']}

            """
            # Check for incomplete connect
            connect_ops = [op for op in operations if op["op"] == "connect"]
            for connect_op in connect_ops:
                if not connect_op["success"] and connect_op.get("incomplete", False):
                    related_syscalls = [
                        {"name": socket_op_list[0]["syscall"].get("call", ""),
                         "args": socket_op_list[0]["syscall"].get("args", []),
                         "error_code": None},
                        {"name": connect_op["syscall"].get("call", ""),
                         "args": connect_op["syscall"].get("args", []),
                         "error_code": None}
                    ]
                    error = {
                        "category": "FIX-IN-PEER", 
                        "description": "FIX_IN_PEER_IPC",
                        "syscalls": related_syscalls,
                        "socket_fd": fd,
                        "socket_family": socket_family,
                        "fix_strategy": "fix_ipc_socket_service",
                        "incomplete_connect": True
                    }
                    if self.is_strategy_enabled(error):
                        return error
            
            # Check for connection refused
            connect_ops = [op for op in operations if op["op"] == "connect"]
            for connect_op in connect_ops:
                if not connect_op["success"] and ("Connection refused" in str(connect_op.get("error_msg", "")) or "No such file or directory" in str(connect_op.get("error_msg", ""))):
                    related_syscalls = [
                        {"name": socket_op_list[0]["syscall"].get("call", ""),
                         "args": socket_op_list[0]["syscall"].get("args", []),
                         "error_code": None},
                        {"name": connect_op["syscall"].get("call", ""),
                         "args": connect_op["syscall"].get("args", []),
                         "error_code": "ECONNREFUSED"}
                    ]
                    error = {
                        "category": "FIX-IN-PEER",
                        "description": "FIX_IN_PEER_IPC",
                        "syscalls": related_syscalls,
                        "socket_fd": fd,
                        "socket_family": socket_family,
                        "fix_strategy": "fix_ipc_socket_service"
                    }
                    if self.is_strategy_enabled(error):
                        return error
            
            # Check for recvfrom errors
            connect_success = any(op["success"] for op in connect_ops)
            if connect_success:
                recvfrom_ops = [op for op in operations if op["op"] in ["recvfrom", "recv"]]
                for recvfrom_op in recvfrom_ops:
                    if not recvfrom_op["success"] and ("Connection refused" in str(recvfrom_op.get("error_msg", "")) or "Connection reset by peer" in str(recvfrom_op.get("error_msg", ""))):
                        successful_connect = next((op for op in connect_ops if op["success"]), None)
                        related_syscalls = [
                            {"name": socket_op_list[0]["syscall"].get("call", ""),
                             "args": socket_op_list[0]["syscall"].get("args", []),
                             "error_code": None},
                            {"name": successful_connect["syscall"].get("call", ""),
                             "args": successful_connect["syscall"].get("args", []),
                             "error_code": None},
                            {"name": recvfrom_op["syscall"].get("call", ""),
                             "args": recvfrom_op["syscall"].get("args", []),
                             "error_code": "ECONNREFUSED"}
                        ]
                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": related_syscalls,
                            "socket_fd": fd,
                            "socket_family": socket_family,
                            "fix_strategy": "fix_ipc_socket_service"
                        }
                        if self.is_strategy_enabled(error):
                            return error
            
            # read()
            for i, op in enumerate(operations):
                if op["op"] == "read" and op.get("size") == 0:
                    prev_ops = operations[:i]
                    has_connect = any(p["op"] == "connect" and p["success"] for p in prev_ops)
                    
                    if has_connect:
                        related_syscalls = []
                        for prev_op in prev_ops:
                            if prev_op["op"] in ["socket", "connect"]:
                                related_syscalls.append({
                                    "name": prev_op["syscall"].get("call", ""),
                                    "args": prev_op["syscall"].get("args", []),
                                    "error_code": None
                                })
                        related_syscalls.append({
                            "name": op["syscall"].get("call", ""),
                            "args": op["syscall"].get("args", []),
                            "error_code": None
                        })
                        
                        error = {
                            "category": "FIX-IN-PEER",
                            "description": "FIX_IN_PEER_IPC",
                            "syscalls": related_syscalls,
                            "socket_fd": fd,
                            "socket_family": socket_family,
                            "fix_strategy": "fix_ipc_socket_service",
                            "read_zero": True
                        }
                        if self.is_strategy_enabled(error):
                            return error

        return None
        
    def check_cwd(self, fs_path, targets, old_cwd):
        """Check if file access failures can be resolved by changing the working directory.

        Returns:
            tuple: (found, new_cwd) where found is True if a better CWD was identified.
        """
        relative_targets = []
        for target in targets:
            if not target.startswith("/") and target not in relative_targets:
                relative_targets.append(target)

        cwds = dict()
        for target in relative_targets:
            # skip none html and cgi files, we can pretty much copy everything else
            ext = target.split(".")[-1]
            if ext not in WEB_EXTS:
                continue
            # check if file might exists somewhere else
            path = os.path.join(fs_path, target)
            sourcefiles = find_files(os.path.basename(target), fs_path, include_backups=True, skip=[path])
            for sourcefile in sourcefiles:
                logger.debug(f"target {target} source {sourcefile}")
                if len(sourcefile) > 0:
                    cwd_path = os.path.dirname(sourcefile)
                    relative_path = os.path.relpath(cwd_path, fs_path)
                    if relative_path not in cwds and relative_path != ".":
                        cwds[relative_path] = 0
                    if relative_path != ".":
                        logger.debug(f"    - adding relative path {target}")
                        cwds[relative_path] += 1

        if len(cwds) <= 0:
            logger.debug("No relative cwd targets found")
            return False, old_cwd

        logger.debug(f"Possible CWDs: {cwds}")
        majority_cwds = []
        highest = 0
        for k, v in cwds.items():
            if v > highest:
                majority_cwds.clear()
                highest = v
            if v >= highest:
                majority_cwds.append(k)
        cwds_sorted = sorted(majority_cwds, key=lambda x: ("www" not in x and "web" not in x and "htm" in x, x.count('/'), len(x), x))
        cwd_path = cwds_sorted[0]
        logger.debug(f"CWD target found: {cwd_path}")
        return True, cwd_path


    def _match_empty_file_reads(self, syscalls):
        """Detect open/read/close sequences followed by crash or non-zero exit.


        Args:
            syscalls: List of parsed syscall events.

        Returns:
            dict: Error pattern if an empty file read is found, or None.
        """
        sequence_id = 0
        operation_sequences = {}
        active_fds = {}
        sequence_paths = {}
        
        # Check if last syscall is a signal, non-zero exit, or other exit syscall
        last_syscall = syscalls[-1]
        last_call = last_syscall.get("call", "")
        last_retval = last_syscall.get("retval", 0)
        
        logger.debug(f"_match_empty_file_reads, last_syscall: {last_syscall}")
        
        is_signal = (last_call == "SIGSEGV" or 
                    last_syscall.get("is_signal", False) or 
                    "SIG" in str(last_syscall.get("details", "")))
                    
        is_nonzero_exit = ((last_call in ["exit", "exit_group"] and last_retval != 0) or
                          last_call.startswith("exit"))
        
        if not (is_signal or is_nonzero_exit):
            return None
        
        # Find last non-ignored open syscall
        last_open_idx = -1
        for i in range(len(syscalls) - 1, -1, -1):
            syscall = syscalls[i]
            name = syscall.get("call")
            if (name == "open" or name == "openat") and not syscall.get("error", False):
                path = syscall.get("file", "")
                if path and not path.startswith(IGNORE_PATH):
                    last_open_idx = i
                    break
        
        # Only process syscalls from last valid open onwards
        for i in range(last_open_idx, len(syscalls)):
            syscall = syscalls[i]
            name = syscall.get("call")
            args = syscall.get("args", [])
            retval = syscall.get("retval", 0)
            error = syscall.get("error", False)
            
            if (name == "open" or name == "openat") and not error and isinstance(retval, int) and retval >= 0:
                try:
                    fd = retval
                    path = syscall.get("file", "")
                    if path:
                        if path.startswith(IGNORE_PATH):
                            continue
                        # Skip NVRAM files (handled separately)
                        if "nvram" in path.lower():
                            continue
                        sequence_id += 1
                        key = (fd, sequence_id)
                        operation_sequences[key] = []
                        operation_sequences[key].append(("open", path, fd, i, syscall))
                        sequence_paths[key] = path
                        active_fds[fd] = sequence_id
                except Exception:
                    pass
            elif name == "read" and not error and len(args) >= 1:
                try:
                    fd = int(args[0])
                    size = retval if isinstance(retval, int) else 0
                    if fd in active_fds:
                        key = (fd, active_fds[fd])
                        has_nonzero_read = any(op[0] == "read" and op[2] > 0
                                               for op in operation_sequences.get(key, []))
                        if size == 0 and has_nonzero_read:
                            pass
                        else:
                            operation_sequences[key].append(("read", sequence_paths.get(key, ""), size, i, syscall))
                except (ValueError, IndexError):
                    pass
            elif name == "close" and not error and len(args) >= 1:
                try:
                    fd = int(args[0])
                    if fd in active_fds:
                        key = (fd, active_fds[fd])
                        operation_sequences[key].append(("close", sequence_paths.get(key, ""), None, i, syscall))
                        del active_fds[fd]
                except (ValueError, IndexError):
                    pass
        
        sorted_keys = sorted(operation_sequences.keys(),
                             key=lambda k: operation_sequences[k][0][3] if operation_sequences[k] else 0,
                             reverse=True)
        
        for key in sorted_keys:
            operations = operation_sequences[key]
            if len(operations) < 3:
                continue
            path = sequence_paths.get(key)
            if not path:
                continue
            if path.startswith(IGNORE_PATH):
                continue
            has_open = operations[0][0] == "open"
            has_close = operations[-1][0] == "close"
            has_read_zero = any(op[0] == "read" and op[2] == 0 for op in operations[1:-1])
            if has_open and has_read_zero and has_close and (operations[-1][3] - operations[0][3] <= 10):
                related_syscalls = []
                for op_type, op_path, size, idx, syscall_obj in operations:
                    related_syscalls.append({
                        "name": syscall_obj.get("call", ""),
                        "args": syscall_obj.get("args", []),
                        "error_code": None
                    })
                error = {
                    "category": "INFER",
                    "description": "INFER_CONTENT",
                    "syscalls": related_syscalls,
                    "path": path,
                    "fix_strategy": "fill_file_content",
                    "operation_sequence": operations
                }
                if self.is_strategy_enabled(error):
                    return error
                # continue

        return None
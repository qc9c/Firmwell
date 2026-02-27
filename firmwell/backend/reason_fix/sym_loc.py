import re
from collections import defaultdict
import angr
import archinfo
from pprint import pprint



open_re = re.compile(r'open\("([^"]+)",O_RDONLY\) = (\d+)')
mmap_re = re.compile(r'mmap2\((0x[0-9a-f]+),(\d+),PROT_EXEC\|PROT_READ,MAP_PRIVATE\|MAP_FIXED,(\d+),')
trace_re = re.compile(r'Trace \d+: 0x[0-9a-fA-F]+ \[\d+/([0-9a-fA-F]+)/\d+/\d+\]')

base_addr = 0x400000

def is_thunk(proj, func, max_insns=5):
    block = proj.factory.block(func.addr, size=64)
    insns = list(block.capstone.insns)
    print(f"len(insns)={len(insns)}")

    if len(insns) > max_insns:
        return False

    if proj.arch.name == 'ARMEL' and len(insns) <= 4:
        mnemonics = [ins.mnemonic.lower() for ins in insns]
        print(f"ARM mnemonics: {mnemonics}")
        
        if ('adr' in mnemonics and 'add' in mnemonics and 
            any('ldr' in mnem for mnem in mnemonics)):
            for ins in insns:
                if ins.mnemonic.lower() == 'ldr' and 'pc' in ins.op_str.lower():
                    print(f"{func.name} is ARM PLT thunk: {ins.mnemonic} {ins.op_str}")
                    return True
        
        for ins in insns:
            if ins.mnemonic.lower() == 'ldr' and 'pc' in ins.op_str.lower():
                print(f"{func.name} is ARM thunk: {ins.mnemonic} {ins.op_str}")
                return True

    # Common jump/branch instruction mnemonics across architectures
    thunk_like_mnemonics = {
        "jmp",         # x86
        "ldr",         # ARM
        "br", "blr",   # ARM64
        "jr", "jalr"   # MIPS
    }

    for ins in insns:
        mnemonic = ins.mnemonic.lower()
        print(mnemonic)
        if mnemonic in thunk_like_mnemonics:
            if "pc" in ins.op_str.lower() or "lr" in ins.op_str.lower() or "x" in ins.op_str.lower():
                print(f"{func.name} is likely a thunk: {mnemonic} {ins.op_str}")
                return True
    return False

def get_func_by_addr(proj, cfg, addr):
    print(f"get_func_by_addr: {hex(addr)}")
    node = cfg.get_any_node(addr)
    if node:
        func = proj.kb.functions.get(node.function_address)
        print(f"Address {hex(addr)} is in function {func.name} at {hex(func.addr)}")
        return func
    else:
        print("No function found at or around address.")
        return None

class ErrorAnalyzer:
    def __init__(self, trace_file_path, filtered_trace_log_path, fs_path, main_binary_path, error_file, excluded_lib_str):
        self.trace_file_path = trace_file_path
        self.filtered_trace_log_path = filtered_trace_log_path
        self.fs_path = fs_path
        self.main_binary_path = main_binary_path
        self.error_file = error_file
        self.excluded_lib_str = excluded_lib_str
        self.base_addr = 0x400000
        
        # Cache for angr projects and CFGs
        self.projects = {}  # binary_path -> (proj, cfg)
        self.merged_map = None

    def extract_lib_mapping(self):
        """
        Extracts library mapping ranges from a given trace file path.
        """
        fd_to_lib = {}
        lib_map = defaultdict(list)

        with open(self.trace_file_path, "r") as f:
            for line in f:
                open_match = open_re.search(line)
                if open_match:
                    lib_path, fd = open_match.groups()
                    fd_to_lib[fd] = lib_path
                    continue

                mmap_match = mmap_re.search(line)
                if mmap_match:
                    addr, size, fd = mmap_match.groups()
                    lib = fd_to_lib.get(fd)
                    if lib:
                        base = int(addr, 16)
                        end = base + int(size)
                        lib_map[lib].append((base, end))

        merged_map = {}
        for lib, ranges in lib_map.items():
            sorted_ranges = sorted(ranges)
            merged = []
            for start, end in sorted_ranges:
                if not merged or start > merged[-1][1]:
                    merged.append([start, end])
                else:
                    merged[-1][1] = max(merged[-1][1], end)
            merged_map[lib] = merged

        return merged_map

    def find_lib_for_address(self, address):
        """
        Find which library an address belongs to.
        Args:
            address: The address to check (as integer)
        Returns:
            The library name if found, None otherwise
        """
        for lib, ranges in self.merged_map.items():
            for start, end in ranges:
                if start <= address < end:
                    return lib
        return None

    def filter_trace_log(self, excluded_lib_ranges):
        """
        Filters the trace log file to exclude lines containing addresses within the specified libraries' ranges.
        """
        with open(self.trace_file_path, "r") as f, open(self.filtered_trace_log_path, "w") as o:
            for line in f:
                # Check if the line starts with "00"
                if line.startswith("00") and "-" not in line:
                    # Extract the address from the line using the new regex
                    # trace_match = trace_re.search(line)
                    # if trace_match:
                    # addr = trace_match.group(1)  # Assuming the address is the first group
                    # base = int(addr, 16)  # Convert address to integer
                    
                    find_addr_str = line
                    base = int(find_addr_str, 16)

                    # Find which library this address belongs to
                    corresponding_lib = self.find_lib_for_address(base)
                    if corresponding_lib is None:
                        continue
                    
                    # Check if the address overlaps with any of the excluded libraries' ranges
                    is_excluded = False
                    for start, end in excluded_lib_ranges:
                        if start <= base < end:
                            is_excluded = True
                            break

                    if not is_excluded:
                        o.write(line)
                else:
                    # Write non-Trace lines directly
                    o.write(line)

    def get_or_create_project(self, binary_path):
        """
        Get or create an angr project for the given binary path.
        Returns:
            Tuple of (proj, cfg)
        """
        if binary_path in self.projects:
            return self.projects[binary_path]
        
        print(f"Creating new angr project for {binary_path}")
        load_options = {'auto_load_libs': False, 'main_opts': {'base_addr': self.base_addr}}
        proj = angr.Project(binary_path, load_options=load_options)
        
        print("Building CFG...")
        cfg = proj.analyses.CFGFast()
        print("CFG built.")
        
        self.projects[binary_path] = (proj, cfg)
        return proj, cfg

    def function_has_relevant_calls(self, proj, cfg, func_addr):
        """
        Check if a function contains calls to open, fopen, or exit functions.
        This helps identify functions that are likely to cause file-related errors.
        Uses a more robust approach that doesn't rely on symbol resolution.
        """
        func = proj.kb.functions.get(func_addr)
        if not func:
            return False
        
        print(f"Checking function {func.name} at {hex(func_addr)} for relevant calls")
        
        has_file_refs = self._function_has_file_references(proj, func)
        if has_file_refs:
            print(f"Function {func.name} contains file path references")
            return True
        
        for call_site in func.get_call_sites():
            call_target = func.get_call_target(call_site)
            if call_target and call_target in proj.kb.functions:
                callee_func = proj.kb.functions[call_target]
                
                if self._is_file_operation_function(callee_func.name):
                    print(f"Function {func.name} calls file operation function {callee_func.name}")
                    return True
                
                # Check if the called function has file references
                if self._function_has_file_references(proj, callee_func):
                    print(f"Function {func.name} calls function {callee_func.name} which has file references")
                    return True
        
        blocks_list = list(func.blocks)
        func_size = getattr(func, 'size', sum(block.size for block in blocks_list))
        if len(blocks_list) <= 2 and func_size <= 32:
            print(f"Function {func.name} is too simple (blocks={len(blocks_list)}, size={func_size})")
            return False
        
        if len(blocks_list) > 5 or func_size > 100:
            print(f"Function {func.name} is complex enough to potentially contain relevant calls")
            return True
        
        print(f"Function {func.name} at {hex(func_addr)} does not appear to contain relevant calls")
        return False
    
    def _is_file_operation_function(self, func_name):
        """Check if function name suggests file operations"""
        file_op_patterns = [
            'open', 'fopen', 'read', 'write', 'close', 'fclose',
            'stat', 'access', 'exists', 'file', 'path', 'dir'
        ]
        func_name_lower = func_name.lower()
        return any(pattern in func_name_lower for pattern in file_op_patterns)
    
    def _function_has_file_references(self, proj, func):
        """Check if function contains references to file paths or file-related strings"""
        try:
            # Look for string references in the function
            blocks_list = list(func.blocks)
            for block in blocks_list:
                for insn_addr in range(block.addr, block.addr + block.size, 4):  # ARM instructions are 4 bytes
                    try:
                        # Try to find data references
                        for xref in proj.kb.xrefs.get_xrefs_by_ins_addr(insn_addr):
                            if xref.type == 'data':
                                # Try to read the data as a string
                                try:
                                    data = proj.loader.memory.load(xref.dst, 64)
                                    if b'/' in data or b'proc' in data or b'dev' in data or b'etc' in data:
                                        return True
                                except:
                                    continue
                    except:
                        continue
            return False
        except:
            # If we can't analyze the function, assume it might be relevant
            return True

    def get_last_trace_line(self, skip_index=0):
        with open(self.filtered_trace_log_path, 'r') as f:
            lines = f.readlines()

        trace_lines_found = 0
        for i in range(len(lines) - 1, 0, -1):
            if self.error_file in lines[i]:
                for j in range(i - 1, -1, -1):
                    # if lines[j].startswith("Trace"):
                    if lines[j].startswith("00"):
                        if trace_lines_found >= skip_index:
                            return lines[j].strip(), trace_lines_found
                        trace_lines_found += 1

        print(f"Error: Could not find a 'Trace' line before a line containing '{self.error_file}' with skip_index={skip_index}")
        return None, None

    def locate_error_bin(self):
        """
        Finds the binary and address that likely led to an error by searching the trace log.
        """
        last_trace_line, trace_index = self.get_last_trace_line()
        if not last_trace_line:
            return None, None

        print("last_trace_line: ", last_trace_line)
        # trace_match = trace_re.search(last_trace_line)
        # if not trace_match:
        #     print(f"Error: Could not parse address from trace line: {last_trace_line}")
        #     return None, None

        # find_addr_str = trace_match.group(1)
        # find_addr = int(find_addr_str, 16)
        
        find_addr_str = last_trace_line
        find_addr = int(find_addr_str, 16)

        err_bin_lib_path = self.find_lib_for_address(find_addr)
        
        binary_path = ""
        if err_bin_lib_path:
            binary_path = self.fs_path.rstrip('/') + err_bin_lib_path
            for start_addr, end_addr in self.merged_map[err_bin_lib_path]:
                if start_addr <= find_addr < end_addr:
                    find_addr -= start_addr
                    break
        else:
            binary_path = self.main_binary_path

        # Get or create angr project
        proj, cfg = self.get_or_create_project(binary_path)
        find_addr += self.base_addr
        
        func = get_func_by_addr(proj, cfg, find_addr)
        if not func:
            return None, None
        func_addr = func.addr

        # Check if the function at the address is a thunk function or doesn't contain relevant calls
        while (proj.kb.functions[func_addr].is_syscall or 
               is_thunk(proj, proj.kb.functions[func_addr]) or
               not self.function_has_relevant_calls(proj, cfg, func_addr)):
            
            if not self.function_has_relevant_calls(proj, cfg, func_addr):
                print(f"Address {hex(find_addr)} function doesn't contain open/exit calls. Looking for the previous 'Trace' line.")
            else:
                print(f"Address {hex(find_addr)} is a thunk function. Looking for the previous 'Trace' line.")
            
            trace_index += 1  # Move to the next trace line
            last_trace_line, _ = self.get_last_trace_line(trace_index)
            if not last_trace_line:
                return None, None

            # trace_match = trace_re.search(last_trace_line)
            # if not trace_match:
            #     print(f"Error: Could not parse address from trace line: {last_trace_line}")
            #     return None, None

            # find_addr_str = trace_match.group(1)
            # find_addr = int(find_addr_str, 16)
            
            find_addr_str = last_trace_line
            find_addr = int(find_addr_str, 16)

            if err_bin_lib_path:
                for start_addr, end_addr in self.merged_map[err_bin_lib_path]:
                    if start_addr <= find_addr < end_addr:
                        find_addr -= start_addr
                        break

            find_addr += self.base_addr
            func = get_func_by_addr(proj, cfg, find_addr)
            if not func:
                return None, None
            func_addr = func.addr

        print(f"Address {hex(find_addr)} is in binary {binary_path}")
        return binary_path, find_addr


    def run_analysis(self):
        """
        Main analysis workflow
        """
        # 1. Extract the mapping ranges of the excluded libraries
        self.merged_map = self.extract_lib_mapping()
        # 
        for lib, ranges in self.merged_map.items():
            for start, end in ranges:
                size = end - start  # 
                print(f"Library: {lib}, Start: {hex(start)}, End: {hex(end)}, Size: {size} bytes")
        
        excluded_lib_ranges = []
        for lib_str in self.excluded_lib_str:
            for lib, ranges in self.merged_map.items():
                if lib_str in lib:
                    excluded_lib_ranges.extend(ranges)
        
        # 2. Filter trace log
        self.filter_trace_log(excluded_lib_ranges)
        print(f"Filtered trace log written to {self.filtered_trace_log_path}")

        # 3. Locate error-causing binary and address
        err_bin_path, find_addr = self.locate_error_bin()
        
        
        # 
        return {
            "analysis_steps": ["extract_lib_mapping", "filter_trace_log", "locate_error_bin"],
            "library_mappings": len(self.merged_map) if self.merged_map else 0,
            "filtered_traces": "completed" if self.filtered_trace_log_path else "not completed"
        }

#!/usr/bin/env python3

import angr
import claripy
import logging
import time
import os
import json

logging.getLogger('angr').setLevel(logging.ERROR)

class NoOpReturnNone(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return args[0] if args else 0

from angr.procedures.stubs.format_parser import ScanfFormatParser
import angr.calling_conventions

class CustomSScanf(ScanfFormatParser):
    """Unified sscanf implementation that handles special format strings"""
    
    def _get_variadic_args(self, count):
        """Get variadic arguments using architecture-aware calling convention"""
        args = []
        arch_name = self.state.arch.name
        ptr_size = self.state.arch.bytes
        
        # Architecture-specific argument passing
        if arch_name in ['X86', 'i386']:
            # x86: all arguments on stack
            sp = self.state.regs.esp
            # Skip return address and first 2 args (src, fmt)
            base_offset = 3 * 4  # 3 * sizeof(void*)
            for i in range(count):
                offset = base_offset + i * 4
                args.append(self.state.memory.load(sp + offset, 4, endness=self.state.arch.memory_endness))
                
        elif arch_name in ['AMD64', 'x86_64']:
            # x86_64: first 6 args in registers, rest on stack
            # For sscanf: arg0=rdi(src), arg1=rsi(fmt), arg2=rdx, arg3=rcx, arg4=r8, arg5=r9, rest on stack
            reg_args = ['rdx', 'rcx', 'r8', 'r9']  # Skip first 2 (rdi, rsi)
            for i in range(count):
                if i < len(reg_args):
                    args.append(getattr(self.state.regs, reg_args[i]))
                else:
                    # Stack arguments
                    sp = self.state.regs.rsp
                    stack_offset = (i - len(reg_args)) * 8
                    args.append(self.state.memory.load(sp + stack_offset, 8, endness=self.state.arch.memory_endness))
                    
        elif arch_name in ['ARMHF', 'ARM', 'ARMEL']:
            # ARM: first 4 args in r0-r3, rest on stack
            # For sscanf: arg0=r0(src), arg1=r1(fmt), arg2=r2, arg3=r3, rest on stack
            reg_args = ['r2', 'r3']  # Skip first 2 (r0, r1)
            for i in range(count):
                if i < len(reg_args):
                    args.append(getattr(self.state.regs, reg_args[i]))
                else:
                    # Stack arguments
                    sp = self.state.regs.sp
                    stack_offset = (i - len(reg_args)) * 4
                    args.append(self.state.memory.load(sp + stack_offset, 4, endness=self.state.arch.memory_endness))
                    
        elif arch_name in ['MIPS32', 'MIPS']:
            # MIPS32: first 4 args in $a0-$a3, rest on stack
            # For sscanf: arg0=$a0(src), arg1=$a1(fmt), arg2=$a2, arg3=$a3, rest on stack
            reg_args = ['a2', 'a3']  # Skip first 2 ($a0, $a1)
            for i in range(count):
                if i < len(reg_args):
                    args.append(getattr(self.state.regs, reg_args[i]))
                else:
                    # Stack arguments
                    sp = self.state.regs.sp
                    stack_offset = (i - len(reg_args)) * 4
                    args.append(self.state.memory.load(sp + stack_offset, 4, endness=self.state.arch.memory_endness))
        else:
            # Generic fallback - assume stack-based
            print(f"Warning: Unknown architecture {arch_name}, using generic stack-based argument passing")
            sp = self.state.regs.sp
            base_offset = 2 * ptr_size  # Skip first 2 args
            for i in range(count):
                offset = base_offset + i * ptr_size
                args.append(self.state.memory.load(sp + offset, ptr_size, endness=self.state.arch.memory_endness))
                
        return args
    
    def extract_components(self, fmt):
        """Parse format string components"""
        components = []
        i = 0
        while i < len(fmt):
            if type(fmt[i]) is bytes and fmt[i] == b"%":
                specifier = b""
                j = i + 1
                while j < len(fmt):
                    if type(fmt[j]) is bytes:
                        specifier += fmt[j]
                        # Check if this completes a format specifier
                        if fmt[j] in b"sdioxXeEfFgGaAcpn":
                            break
                    j += 1
                
                specifier = self._match_spec(specifier)
                if specifier is not None:
                    i = j + 1
                    components.append(specifier)
                else:
                    i += 1
                    components.append(b"%")
            else:
                components.append(fmt[i])
                i += 1
        
        return components
    
    def _is_mtd_format(self, fmt_str):
        """Check if this is the special MTD format string"""
        try:
            # Get the format string from memory
            fmt_bytes = self.state.solver.eval(self.state.memory.load(fmt_str, 64), cast_to=bytes)
            fmt_text = fmt_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
            # Check if it matches the MTD format
            return fmt_text == '%31s %31s %31s "%31[^"]"'
        except Exception:
            return False
    
    def _handle_mtd_format(self, src, fmt):
        """Handle the special MTD format string: '%31s %31s %31s "%31[^"]"'"""
        # Get variadic arguments using architecture-aware method
        args = self._get_variadic_args(4)  # We need 4 arguments for sscanf
        
        try:
            src_str = self.state.memory.load(src, 128)
            
            # Check if input is symbolic
            if self.state.solver.symbolic(src_str):
                print("CustomSScanf: processing symbolic MTD format")
                
                try:
                    # Extract parts based on the known MTD structure
                    # Device name: positions 0-3 ("mtdX")
                    device_bytes = []
                    for i in range(4):
                        device_bytes.append(src_str.get_byte(i))
                    device_part = claripy.Concat(*device_bytes, claripy.BVV(0, 8))
                    self.state.memory.store(args[0], device_part)
                    
                    # Size: positions 5-12 ("00000000")
                    size_bytes = []
                    for i in range(5, 13):
                        size_bytes.append(src_str.get_byte(i))
                    size_part = claripy.Concat(*size_bytes, claripy.BVV(0, 8))
                    self.state.memory.store(args[1], size_part)
                    
                    # Erasesize: positions 14-21 ("00000000")
                    erase_bytes = []
                    for i in range(14, 22):
                        erase_bytes.append(src_str.get_byte(i))
                    erase_part = claripy.Concat(*erase_bytes, claripy.BVV(0, 8))
                    self.state.memory.store(args[2], erase_part)
                    
                    # Partition name: starts at position 25 (after quote)
                    name_bytes = []
                    for i in range(25, 25 + 31):  # Max 31 chars
                        if i < src_str.size() // 8:
                            byte_val = src_str.get_byte(i)
                            name_bytes.append(byte_val)
                        else:
                            break
                    
                    if name_bytes:
                        name_part = claripy.Concat(*name_bytes, claripy.BVV(0, 8))
                        self.state.memory.store(args[3], name_part)
                    else:
                        self.state.memory.store(args[3], claripy.BVV(0, 8))
                    
                    print("CustomSScanf: extracted symbolic MTD parts")
                    return 4
                    
                except Exception as e:
                    print(f"CustomSScanf: error processing symbolic MTD input: {e}")
                    return 0
            
            # Handle concrete input for MTD format
            src_bytes = self.state.solver.eval(src_str, cast_to=bytes)
            src_text = src_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
            
            print(f"CustomSScanf parsing MTD format: '{src_text}'")
            
            # Parse the MTD format: device_name: size erasesize "partition_name"
            import re
            pattern = r'(\S+):\s+(\S+)\s+(\S+)\s+"([^"]+)"'
            src_clean = src_text.strip()
            match = re.match(pattern, src_clean)
            
            # Alternative parsing if regex fails
            if not match:
                parts = src_clean.split()
                if len(parts) >= 4:
                    quoted_start = src_clean.find('"')
                    quoted_end = src_clean.rfind('"')
                    if quoted_start >= 0 and quoted_end > quoted_start:
                        quoted_part = src_clean[quoted_start+1:quoted_end]
                        match = type('FakeMatch', (), {
                            'groups': lambda: (parts[0].rstrip(':'), parts[1], parts[2], quoted_part)
                        })()
            
            if match and len(args) >= 4:
                groups = match.groups()
                print(f"CustomSScanf parsed MTD groups: {groups}")
                
                for i, (arg, value) in enumerate(zip(args[:4], groups)):
                    value_bytes = value.encode('utf-8') + b'\x00'
                    self.state.memory.store(arg, value_bytes)
                
                return 4
            else:
                print(f"CustomSScanf: MTD format parsing failed")
                return 0
                
        except Exception as e:
            print(f"CustomSScanf MTD error: {e}")
            import traceback
            traceback.print_exc()
            return 0
    
    def run(self, src, fmt):
        """Main sscanf implementation with format detection"""
        try:
            # Check if this is the special MTD format string
            if self._is_mtd_format(fmt):
                print("CustomSScanf: Detected MTD format string")
                return self._handle_mtd_format(src, fmt)
            else:
                print("CustomSScanf: Using general format parsing")
                # Use the general ScanfFormatParser implementation
                fmt_str = self._parse(fmt)
                return fmt_str.interpret(self.va_arg, addr=src)
                
        except Exception as e:
            print(f"CustomSScanf error: {e}")
            import traceback
            traceback.print_exc()
            return 0


from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

class SymbolicFgets(angr.SimProcedure):
    """Custom fgets that properly handles symbolic data for line-by-line reading"""
    def run(self, dst, size, file_ptr):
        size = size.zero_extend(self.arch.bits - self.arch.sizeof["int"])
        
        # Get file descriptor
        try:
            fd_offset = io_file_data_for_arch(self.state.arch)['fd']
            fd = self.state.mem[file_ptr + fd_offset:].int.resolved
            simfd = self.state.posix.get_fd(fd)
            if simfd is None:
                return 0
        except Exception as e:
            print(f"SymbolicFgets: Failed to get fd: {e}")
            return 0

        # Case 0: empty read
        if self.state.solver.is_true(size == 0):
            return 0

        max_size = self.state.solver.eval(size) - 1
        
        # Read byte by byte until newline or EOF or max_size
        count = 0
        while count < max_size:
            try:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    # EOF reached
                    break
                    
                # Store the byte
                self.state.memory.store(dst + count, data)
                count += 1
                
                # Check if it's a newline - for symbolic data, we need to check symbolically
                if simfd.read_storage.concrete:
                    if self.state.solver.is_true(data == b"\n"):
                        break
                else:
                    # For symbolic data, check if this could be a newline
                    byte_val = data.get_byte(0) if hasattr(data, 'get_byte') else data
                    if self.state.solver.is_true(byte_val == ord('\n')):
                        break
                        
            except Exception as e:
                print(f"SymbolicFgets: Error reading byte {count}: {e}")
                break
        
        # Add null terminator
        self.state.memory.store(dst + count, claripy.BVV(0, 8))
        
        return claripy.BVV(count, self.arch.bits) if count > 0 else claripy.BVV(0, self.arch.bits)

class OnDemandSimFile(angr.SimProcedure):
    def __init__(self, fs_path, error_file=None):
        super().__init__()
        self.fs_path = fs_path
        self.error_file = error_file
        
    def run(self, pathname, flags, *args):
        # pathname is always a pointer to string in memory
        try:
            path_str = self.state.solver.eval(self.state.memory.load(pathname, 256), cast_to=bytes)
            path_str = path_str.split(b'\x00')[0]
        except Exception as e:
            print(f"Failed to read path from memory at {hex(pathname) if isinstance(pathname, int) else pathname}: {e}")
            return -1
        
        print(f"OnDemandSimFile: Trying to open file: {path_str}")
        
        # Handle empty path
        if not path_str:
            print("OnDemandSimFile: Empty path, returning error")
            return -1
            
        path_str_decoded = path_str.decode('utf-8', errors='ignore')
        
        # Check if this is the error file - if so, skip loading from disk
        # The error file should already have symbolic content set up in run_symbolic_execution
        if self.error_file and path_str_decoded == self.error_file:
            print(f"OnDemandSimFile: Skipping load for error file {self.error_file} (already symbolic)")
            # Just open the already inserted symbolic file
            fd = self.state.posix.open(path_str_decoded, flags)
            return fd
        
        def get_rel_path(path):
            if path.startswith('/'):
                return path[1:]
            return path
        
        # For all other files, load from disk on demand
        if not self.state.fs.get(path_str_decoded):
            real_path = os.path.join(self.fs_path, get_rel_path(path_str_decoded))
            
            if os.path.exists(real_path):
                try:
                    with open(real_path, 'rb') as f:
                        content = f.read()
                    print(f"OnDemandSimFile: Loaded {len(content)} bytes from {real_path}")
                    simfile = angr.storage.SimFile(path_str_decoded, content=content, size=len(content), has_end=True)
                    self.state.fs.insert(path_str_decoded, simfile)
                except Exception as e:
                    print(f"OnDemandSimFile: Error reading {real_path}: {e}")
                    content = b''
                    simfile = angr.storage.SimFile(path_str_decoded, content=content, size=0, has_end=True)
                    self.state.fs.insert(path_str_decoded, simfile)
            else:
                print(f"OnDemandSimFile: File not found: {real_path}")
                content = b''
                simfile = angr.storage.SimFile(path_str_decoded, content=content, size=0, has_end=True)
                self.state.fs.insert(path_str_decoded, simfile)
        
        fd = self.state.posix.open(path_str_decoded, flags)
        return fd

class OnDemandSimFileFopen(angr.SimProcedure):
    def __init__(self, fs_path, error_file=None):
        super().__init__()
        self.fs_path = fs_path
        self.error_file = error_file
        
    def run(self, pathname, mode):
        # pathname is always a pointer to string in memory
        try:
            path_str = self.state.solver.eval(self.state.memory.load(pathname, 256), cast_to=bytes)
            path_str = path_str.split(b'\x00')[0]
        except Exception as e:
            print(f"Failed to read path from memory at {hex(pathname) if isinstance(pathname, int) else pathname}: {e}")
            return 0
        
        print(f"OnDemandSimFileFopen: Trying to fopen file: {path_str}")
        
        # Handle empty path
        if not path_str:
            print("OnDemandSimFileFopen: Empty path, returning NULL")
            return 0
            
        path_str_decoded = path_str.decode('utf-8', errors='ignore')
        
        # Check if this is the error file - if so, skip loading from disk
        if self.error_file and path_str_decoded == self.error_file:
            print(f"OnDemandSimFileFopen: Skipping load for error file {self.error_file} (already symbolic)")
        else:
            def get_rel_path(path):
                if path.startswith('/'):
                    return path[1:]
                return path
            
            # For all other files, load from disk on demand
            if not self.state.fs.get(path_str_decoded):
                real_path = os.path.join(self.fs_path, get_rel_path(path_str_decoded))
                
                if os.path.exists(real_path):
                    try:
                        with open(real_path, 'rb') as f:
                            content = f.read()
                        print(f"OnDemandSimFileFopen: Loaded {len(content)} bytes from {real_path}")
                        simfile = angr.storage.SimFile(path_str_decoded, content=content, size=len(content), has_end=True)
                        self.state.fs.insert(path_str_decoded, simfile)
                    except Exception as e:
                        print(f"OnDemandSimFileFopen: Error reading {real_path}: {e}")
                        content = b''
                        simfile = angr.storage.SimFile(path_str_decoded, content=content, size=0, has_end=True)
                        self.state.fs.insert(path_str_decoded, simfile)
                else:
                    print(f"OnDemandSimFileFopen: File not found: {real_path}")
                    content = b''
                    simfile = angr.storage.SimFile(path_str_decoded, content=content, size=0, has_end=True)
                    self.state.fs.insert(path_str_decoded, simfile)
        
        mode_str = self.state.solver.eval(self.state.memory.load(mode, 8), cast_to=bytes).split(b'\x00')[0].decode()
        flags = 0
        if 'r' in mode_str:
            flags = 0  # O_RDONLY
        elif 'w' in mode_str:
            flags = 1  # O_WRONLY
        elif 'a' in mode_str:
            flags = 1  # O_WRONLY with append
        
        fd = self.state.posix.open(path_str_decoded, flags)
        if fd < 0:
            return 0
        
        if fd >= 0:
            # Allocate a FILE structure
            file_ptr = self.state.heap._malloc(0x100)
            fd_offset = io_file_data_for_arch(self.state.arch)['fd']
            # Store the file descriptor in the FILE structure
            self.state.memory.store(file_ptr+fd_offset, self.state.solver.BVV(fd, self.state.arch.bits), endness=self.state.arch.memory_endness)
            return file_ptr
        else:
            return 0
        
class FakePopen(angr.SimProcedure):
    def run(self, cmd, mode):
        fake_content = b"dummy\n"
        fake_file = angr.storage.SimFile("fake_pipe", content=fake_content, size=len(fake_content), has_end=True)
        self.state.fs.insert("fake_pipe", fake_file)
        fd = self.state.posix.open("fake_pipe", 0)
        return fd
    
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
    

def get_arch_info(arch):
    """Get architecture-specific information"""
    info = {
        'name': arch.name,
        'bits': arch.bits,
        'bytes': arch.bytes,
        'memory_endness': arch.memory_endness,
        'stack_ptr': None,
        'supported': True
    }
    
    # Set architecture-specific stack pointer register name
    if arch.name in ['ARMHF', 'ARM', 'ARMEL']:
        info['stack_ptr'] = 'sp'
    elif arch.name in ['X86', 'i386']:
        info['stack_ptr'] = 'esp'
    elif arch.name in ['AMD64', 'x86_64']:
        info['stack_ptr'] = 'rsp'
    elif arch.name in ['MIPS32', 'MIPS']:
        info['stack_ptr'] = 'sp'
    else:
        info['supported'] = False
        info['stack_ptr'] = 'sp'  # fallback
    
    return info

class SymbolicExecutor:
    def __init__(self, err_bin_path, find_addr, fs_path, error_file=None, output_dir=None):
        self.err_bin_path = err_bin_path
        self.find_addr = find_addr
        self.fs_path = fs_path
        self.error_file = error_file
        self.output_dir = output_dir
        self.proj = None
        self.cfg = None
        
        print(f"err_bin_path: {self.err_bin_path}")
        print(f"find_addr: {hex(self.find_addr)}")
        print(f"fs_path: {self.fs_path}")
        print(f"error_file: {self.error_file}")
        print(f"output_dir: {self.output_dir}")
    
    def _setup_mtd_symbolic_file(self, state):
        """Set up symbolic file for /proc/mtd with structured format"""
        # Experimental: Make device numbers symbolic while keeping "mtd" prefix
        # This allows the solver to discover the correct device numbers
        
        # Create symbolic device numbers (single digit 1-9)
        num1 = claripy.BVS('device_num1', 8)  # Single byte for device number
        num2 = claripy.BVS('device_num2', 8)  # Single byte for device number
        
        # Constrain device numbers to be digits 1-9 (avoid 0 to prevent atoi <= 0)
        state.add_constraints(num1 >= ord('1'))
        state.add_constraints(num1 <= ord('9'))
        state.add_constraints(num2 >= ord('1'))
        state.add_constraints(num2 <= ord('9'))
        
        # Create symbolic partition names WITHOUT any magic bytes
        name1 = claripy.BVS('partition1', 32 * 8)  # Max 31 chars as per sscanf format
        name2 = claripy.BVS('partition2', 32 * 8)  # Max 31 chars as per sscanf format
        
        # Only add basic printable ASCII constraints - no magic values!
        for i in range(32):
            byte1 = name1.get_byte(i)
            byte2 = name2.get_byte(i)
            # Allow printable ASCII characters and null terminator
            state.add_constraints(
                claripy.Or(
                    byte1 == 0,  # null terminator
                    claripy.And(byte1 >= 32, byte1 <= 126)  # printable ASCII
                )
            )
            state.add_constraints(
                claripy.Or(
                    byte2 == 0,  # null terminator
                    claripy.And(byte2 >= 32, byte2 <= 126)  # printable ASCII
                )
            )
        
        # Create the /proc/mtd content with symbolic device numbers
        # Format: mtd{num}: 00000000 00000000 "{partition_name}"
        
        # Create lines with symbolic device numbers but fixed mtd prefix
        line1 = claripy.Concat(
            claripy.BVV(b'mtd', 3 * 8),      # Fixed "mtd" prefix
            num1,                              # Symbolic device number
            claripy.BVV(b': 00000000 00000000 "', 21 * 8),  # Fixed middle part
            name1,                             # Symbolic partition name
            claripy.BVV(b'"\n', 2 * 8)       # Fixed ending
        )
        
        line2 = claripy.Concat(
            claripy.BVV(b'mtd', 3 * 8),      # Fixed "mtd" prefix
            num2,                              # Symbolic device number
            claripy.BVV(b': 00000000 00000000 "', 21 * 8),  # Fixed middle part
            name2,                             # Symbolic partition name
            claripy.BVV(b'"\n', 2 * 8)       # Fixed ending  
        )
        
        full_content = claripy.Concat(line1, line2)
        # File size calculation: mtd + num + middle + name + ending (per line) * 2
        file_size = (3 + 1 + 21 + 32 + 2) * 2  # Max size with symbolic numbers and 32-char names
        
        # Create SimFile with symbolic content
        error_simfile = angr.storage.SimFile(
            self.error_file,
            content=full_content,
            size=file_size,
            has_end=True
        )
        state.fs.insert(self.error_file, error_simfile)
        
        print(f"Set up symbolic /proc/mtd format for: {self.error_file}")
        print(f"File size: {file_size} bytes")
        print(f"Symbolic device numbers (1-9) and partition names (up to 31 chars each)")
        
        # Store for later solution extraction
        self.error_file_sym = full_content
        self.num1_sym = num1
        self.num2_sym = num2
        self.name1_sym = name1
        self.name2_sym = name2
    
    def _setup_general_symbolic_file(self, state):
        """Set up general symbolic file for non-MTD files"""
        file_size = 256
        error_file_sym = claripy.BVS("error_file_content", file_size * 8)
        
        # Add basic constraints for printable content
        for i in range(file_size):
            byte_val = error_file_sym.get_byte(i)
            # Allow printable ASCII characters, whitespace, and null terminator
            state.add_constraints(
                claripy.Or(
                    byte_val == 0,  # null terminator
                    claripy.And(byte_val >= 9, byte_val <= 13),   # whitespace chars
                    claripy.And(byte_val >= 32, byte_val <= 126)  # printable ASCII
                )
            )
        
        error_simfile = angr.storage.SimFile(
            self.error_file, 
            content=error_file_sym, 
            size=file_size, 
            has_end=True
        )
        state.fs.insert(self.error_file, error_simfile)
        
        print(f"Set up general symbolic content for: {self.error_file}")
        print(f"File size: {file_size} bytes")
        
        # Store for later solution extraction
        self.error_file_sym = error_file_sym
        
    def run_symbolic_execution(self):
        
        start_time = time.time()
        print(f"Using binary: {self.err_bin_path}")
        proj = angr.Project(self.err_bin_path, load_options={'auto_load_libs': False})
        
        # Check architecture compatibility
        arch_info = get_arch_info(proj.arch)
        print(f"Architecture: {arch_info['name']} ({arch_info['bits']}-bit, {arch_info['memory_endness']})")
        if not arch_info['supported']:
            print(f"Warning: Architecture {arch_info['name']} may not be fully supported")
        
        print(f"self.find_addr: {hex(self.find_addr)}")
        cfg = proj.analyses.CFGFast(force_complete_scan=False)
        func = get_func_by_addr(proj, cfg, self.find_addr)
        func_addr = func.addr
        print(f"func_addr: {hex(func.addr)}")
        
        
        # Create initial state
        state = proj.factory.call_state(addr=func_addr, args=[0])
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        # Add option to handle symbolic addresses
        state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        # Make constraint solving more lenient
        state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
        
        # Initialize global variables to 0 (not set)
        # Based on the C code, dword_16380 and dword_1637C need to be 0 initially
        # These are likely at fixed addresses in the .data or .bss section
        # We'll let angr handle this through ZERO_FILL_UNCONSTRAINED_MEMORY
        
        # Hook file opening functions with OnDemandSimFile
        proj.hook_symbol("open", OnDemandSimFile(self.fs_path, self.error_file))
        proj.hook_symbol("fopen", OnDemandSimFileFopen(self.fs_path, self.error_file))
        
        # Use a simple fgets that reads line by line
        class LineByLineFgets(angr.SimProcedure):
            def run(self, dst, size, file_ptr):
                from cle.backends.externs.simdata.io_file import io_file_data_for_arch
                
                try:
                    fd_offset = io_file_data_for_arch(self.state.arch)['fd']
                    fd = self.state.mem[file_ptr + fd_offset:].int.resolved
                    simfd = self.state.posix.get_fd(fd)
                    if simfd is None:
                        return 0
                except:
                    return 0
                
                max_size = self.state.solver.eval(size) - 1
                count = 0
                
                # Read byte by byte until newline or max_size
                while count < max_size:
                    data, real_size = simfd.read_data(1)
                    if self.state.solver.is_true(real_size == 0):
                        # EOF
                        break
                    
                    # Store the byte
                    self.state.memory.store(dst + count, data)
                    count += 1
                    
                    # Check for newline - if symbolic, we can't easily check
                    # but we need to stop at newlines for proper line reading
                    if not self.state.solver.symbolic(data):
                        byte_val = self.state.solver.eval(data, cast_to=int)
                        if byte_val == ord('\n'):
                            break
                    else:
                        # For symbolic data, assume reasonable line lengths
                        if count >= 50:  # Reasonable line length
                            break
                
                # Add null terminator
                self.state.memory.store(dst + count, claripy.BVV(0, 8))
                return count if count > 0 else 0
        
        proj.hook_symbol('fgets', LineByLineFgets())
        
        # Set up symbolic file based on file type
        if self.error_file:
            if self.error_file == "/proc/mtd":
                print("Using MTD-specific symbolic file setup")
                self._setup_mtd_symbolic_file(state)
            else:
                print("Using general symbolic file setup")
                self._setup_general_symbolic_file(state)
        
        # Hook other external functions
        try:
            proj.hook_symbol('__isoc99_sscanf', CustomSScanf())
        except:
            pass  # Symbol might not exist
        proj.hook_symbol('sscanf', CustomSScanf())
        proj.hook_symbol('memset', NoOpReturnNone())
        
        # Hook exit to track when it's called
        class FakeExit(angr.SimProcedure):
            def run(self, code):
                self.state.globals['exit_called'] = True
                self.exit(code)
        
        # Hook symbols
        proj.hook_symbol("popen", FakePopen())
        proj.hook_symbol("exit", FakeExit())
        proj.hook_symbol('__isoc99_sscanf', CustomSScanf())
        proj.hook_symbol('sscanf', CustomSScanf())
        proj.hook_symbol('memset', NoOpReturnNone())
        
        # Hook atoi to parse mtd numbers correctly
        class CustomAtoi(angr.SimProcedure):
            def run(self, s):
                try:
                    s_str = self.state.memory.load(s, 16)
                    s_bytes = self.state.solver.eval(s_str, cast_to=bytes)
                    s_text = s_bytes.split(b'\x00')[0].decode('utf-8')
                    print(f"atoi called with: '{s_text}' (first few chars: {s_text[:5] if len(s_text) >= 5 else s_text})")
                    # Extract number from strings
                    import re
                    # Handle both "0", "1", etc and strings that might have been parsed
                    if s_text.isdigit():
                        num = int(s_text)
                        print(f"atoi('{s_text}') = {num}")
                        return num
                    else:
                        match = re.search(r'(\d+)', s_text)
                        if match:
                            num = int(match.group(1))
                            print(f"atoi('{s_text}') = {num}")
                            return num
                        else:
                            print(f"atoi('{s_text}') = 0 (no number found)")
                            return 0
                except Exception as e:
                    print(f"atoi error: {e}")
                    return 0
        
        proj.hook_symbol('atoi', CustomAtoi())

        
        # Get the function at the specified address
        func = None
        if func_addr not in proj.kb.functions:
            print(f"Warning: No function found at {hex(func_addr)}, trying to find nearest function")
            # Find the function containing this address
            for f_addr, f in proj.kb.functions.items():
                if hasattr(f, 'size') and f.addr <= func_addr < f.addr + f.size:
                    print(f"Found containing function {f.name} at {hex(f.addr)}")
                    func = f
                    func_addr = f.addr  # Use the function start address
                    break
            if not func:
                print("Error: Could not find function containing the address")
                return None
        else:
            func = proj.kb.functions[func_addr]
        
        print(f"Using function {func.name} at {hex(func_addr)}")
            
        exit_blocks = []
        blocks_list = list(func.blocks)
        arch_name = proj.arch.name
        
        for block in blocks_list:
            if hasattr(block, 'capstone') and block.capstone.insns:
                last_insn = block.capstone.insns[-1]
                is_return = False
                
                # Architecture-specific return instruction detection
                if arch_name in ['ARMHF', 'ARM', 'ARMEL']:
                    # ARM return patterns
                    if last_insn.mnemonic == "mov":
                        ops = [op.strip() for op in last_insn.op_str.split(',')]
                        if len(ops) == 2 and ops[0].lower() == "pc" and ops[1].lower() == "lr":
                            is_return = True
                    elif last_insn.mnemonic == "pop":
                        if "pc" in last_insn.op_str.lower():
                            is_return = True
                    elif last_insn.mnemonic == "bx":
                        if "lr" in last_insn.op_str.lower():
                            is_return = True
                            
                elif arch_name in ['X86', 'i386']:
                    # x86 return patterns
                    if last_insn.mnemonic in ["ret", "retn"]:
                        is_return = True
                        
                elif arch_name in ['AMD64', 'x86_64']:
                    # x86_64 return patterns
                    if last_insn.mnemonic in ["ret", "retq"]:
                        is_return = True
                        
                elif arch_name in ['MIPS32', 'MIPS']:
                    # MIPS return patterns
                    if last_insn.mnemonic == "jr" and "$ra" in last_insn.op_str:
                        is_return = True
                    elif last_insn.mnemonic == "j" and "$ra" in last_insn.op_str:
                        is_return = True
                else:
                    # Generic fallback - look for common return patterns
                    if last_insn.mnemonic in ["ret", "return", "jr"]:
                        is_return = True
                
                if is_return:
                    exit_blocks.append(block.addr)
        
        if exit_blocks:
            ret_addr = exit_blocks[0]
            print(f"Found return address: {hex(ret_addr)}")
        else:
            print("Warning: Could not find return address, will run without return address checking")
            ret_addr = None
            exit(0)
        
        # Create and run simulation manager
        simgr = proj.factory.simulation_manager(state)
        
        print("Starting symbolic execution...")
        if ret_addr:
            print(f"DEBUG: Return address: {hex(ret_addr)}")
        print(f"DEBUG: Initial simgr: {simgr}")
        
        # Add a hook to see what's happening when strcmp is called
        def strcmp_hook(state):
            # Get arguments to strcmp using architecture-aware method
            arch_name = state.arch.name
            
            if arch_name in ['ARMHF', 'ARM', 'ARMEL']:
                arg1_ptr = state.regs.r0
                arg2_ptr = state.regs.r1
            elif arch_name in ['X86', 'i386']:
                # x86: arguments on stack
                sp = state.regs.esp
                arg1_ptr = state.memory.load(sp + 4, 4, endness=state.arch.memory_endness)
                arg2_ptr = state.memory.load(sp + 8, 4, endness=state.arch.memory_endness)
            elif arch_name in ['AMD64', 'x86_64']:
                arg1_ptr = state.regs.rdi
                arg2_ptr = state.regs.rsi
            elif arch_name in ['MIPS32', 'MIPS']:
                arg1_ptr = state.regs.a0
                arg2_ptr = state.regs.a1
            else:
                # Generic fallback - assume first two args are in first available registers
                return
            try:
                # Try to read the strings
                arg1 = state.memory.load(arg1_ptr, 32)
                arg2 = state.memory.load(arg2_ptr, 32)
                if not state.solver.symbolic(arg1) and not state.solver.symbolic(arg2):
                    arg1_bytes = state.solver.eval(arg1, cast_to=bytes).split(b'\x00')[0]
                    arg2_bytes = state.solver.eval(arg2, cast_to=bytes).split(b'\x00')[0]
                    
                    print(f"strcmp at {hex(state.addr)}: '{arg1_bytes.decode()}' vs '{arg2_bytes.decode()}' = {arg1_bytes == arg2_bytes}")

            except:
                pass
        
        # Hook strcmp to see what's being compared
        proj.hook_symbol('strcmp', angr.SIM_PROCEDURES['libc']['strcmp']())
        
        step_count = 0
        while simgr.active:
            # Check for strcmp calls
            for active in simgr.active:
                if proj.is_hooked(active.addr):
                    func = proj.hooked_by(active.addr)
                    if hasattr(func, 'display_name') and 'strcmp' in str(func.display_name):
                        strcmp_hook(active)
            
            simgr.step()
            step_count += 1
            
            # Print debug info every 50 steps
            if step_count % 50 == 0:
                print(f"DEBUG: Step {step_count}, simgr: {simgr}")
                for i, s in enumerate(simgr.active):
                    print(f"  Active state {i}: addr={hex(s.addr)}, exit_called={s.globals.get('exit_called', False)}")
                for i, s in enumerate(simgr.deadended):
                    print(f"  Deadended state {i}: addr={hex(s.addr)}, exit_called={s.globals.get('exit_called', False)}")
            
            # Check if we reached the return address
            ret_states = [s for s in simgr.active if s.addr == ret_addr]
            if ret_states:
                print(f"DEBUG: Found {len(ret_states)} states at return address {hex(ret_addr)}")
                for i, s in enumerate(ret_states):
                    print(f"  Return state {i}: addr={hex(s.addr)}, exit_called={s.globals.get('exit_called', False)}")
                break
        
        print(f"DEBUG: Final simgr after {step_count} steps: {simgr}")
        print(f"DEBUG: Final active states:")
        for i, s in enumerate(simgr.active):
            print(f"  Active state {i}: addr={hex(s.addr)}, exit_called={s.globals.get('exit_called', False)}")
        print(f"DEBUG: Final deadended states:")
        for i, s in enumerate(simgr.deadended):
            print(f"  Deadended state {i}: addr={hex(s.addr)}, exit_called={s.globals.get('exit_called', False)}")
        
        print(simgr)
        
        # Find valid states - exit
        valid_states = []
        print(f"DEBUG: Checking for valid states at return address {hex(ret_addr)}")
        all_states = simgr.deadended + simgr.active
        print(f"DEBUG: Total states to check: {len(all_states)}")
        
        for i, s in enumerate(all_states):
            exit_called = 'exit_called' in s.globals
            at_ret_addr = s.addr == ret_addr
            print(f"DEBUG: State {i}: addr={hex(s.addr)}, exit_called={exit_called}, at_ret_addr={at_ret_addr}")
            
            if not exit_called and at_ret_addr:
                valid_states.append(s)
                print(f"DEBUG: State {i} is VALID!")
        
        print(f"DEBUG: Found {len(valid_states)} valid states")
        
        
        if simgr.errored:
            print("=== Errored states: ===")
            for s in simgr.errored:
                addr = getattr(s, 'addr', None)
                print(f"  State at addr {hex(addr) if addr else '??'}")
                # Angr SimState stores the exception object in .error
                if hasattr(s, 'error') and s.error is not None:
                    print(f"    Exception: {s.error}")
                else:
                    print("    (No exception info available)")
        
        if valid_states:
            
            for found_state in valid_states:
                print("\n...")
                
                try:
                    print("Found valid state!")
                    
                    if self.error_file == "/proc/mtd":
                        # MTD-specific solution extraction with symbolic device numbers
                        if (hasattr(self, 'num1_sym') and hasattr(self, 'num2_sym') and 
                            hasattr(self, 'name1_sym') and hasattr(self, 'name2_sym')):
                            
                            # Extract symbolic device numbers and partition names
                            num1_byte = found_state.solver.eval(self.num1_sym, cast_to=int)
                            num2_byte = found_state.solver.eval(self.num2_sym, cast_to=int)
                            name1_bytes = found_state.solver.eval(self.name1_sym, cast_to=bytes)
                            name2_bytes = found_state.solver.eval(self.name2_sym, cast_to=bytes)
                            
                            # Convert device numbers to characters
                            num1_char = chr(num1_byte)
                            num2_char = chr(num2_byte)
                            
                            # Clean up the symbolic names
                            def clean_string(byte_data):
                                str_data = byte_data.decode('utf-8', errors='ignore')
                                clean_str = ""
                                for c in str_data:
                                    if ord(c) == 0 or ord(c) < 32 or ord(c) > 126:
                                        break
                                    clean_str += c
                                return clean_str
                            
                            name1_str = clean_string(name1_bytes)
                            name2_str = clean_string(name2_bytes)
                            
                            # Output with discovered device numbers
                            solution_str = f'mtd{num1_char}: 00000000 00000000 "{name1_str}"\nmtd{num2_char}: 00000000 00000000 "{name2_str}"\n'
                            
                            print("MTD symbolic solution found (with symbolic device numbers):")
                            print(solution_str)
                            
                            # Save to JSON
                            solution_data = {
                                "error_file": self.error_file,
                                "solution": solution_str,
                            }
                        else:
                            print("Error: MTD symbolic variables not found")
                            continue
                    else:
                        # General solution extraction
                        if hasattr(self, 'error_file_sym') and self.error_file_sym is not None:
                            original_solution_bytes = found_state.solver.eval(self.error_file_sym, cast_to=bytes)
                            
                            # Clean up the solution string
                            try:
                                solution_str = original_solution_bytes.decode('utf-8', errors='ignore')
                                # Remove trailing null bytes and clean up
                                solution_str = solution_str.rstrip('\x00')
                            except Exception as e:
                                print(f"UTF-8 decode error: {e}, using repr")
                                solution_str = repr(original_solution_bytes)
                                
                            print("General symbolic solution found:")
                            print(repr(solution_str))
                            
                            # Save to JSON
                            solution_data = {
                                "error_file": self.error_file,
                                "solution": solution_str
                            }
                        else:
                            print("Error: General symbolic variable not found")
                            continue
                    
                    output_filepath = os.path.join(self.output_dir, "solution.json")
                    with open(output_filepath, "w") as f:
                        json.dump(solution_data, f, indent=4)
                    print(f"Solution saved to: {output_filepath}")
                    
                    # Return success result
                    return [{"output_file": output_filepath, "solution_data": solution_data}]
                    
                except Exception as e:
                    print(f"Error extracting solution: {e}")
        else:
            print(" exit(1) ")
            
            # 
            exit_states = sum(1 for s in simgr.deadended + simgr.active if 'exit_called' in s.globals)
            print(f"exit: {exit_states}")
            print(f"deadended: {len(simgr.deadended)}")
            print(f": {len(simgr.active)}")
        end_time = time.time()
        print(f": {end_time - start_time} ")
        
        # Return empty list if no solutions found
        return []


if __name__ == "__main__":
    import argparse
    import sys
    
    sym_exe = SymbolicExecutor(
        err_bin_path="/tmp/e393a356a812a938e06de46cd2bcba0644ceeb4e3ed71984009b42909cece7c0/fs/usr/lib/libntgrcrypt.so",
        find_addr=0x401ed8,  # Example address
        fs_path="/tmp/e393a356a812a938e06de46cd2bcba0644ceeb4e3ed71984009b42909cece7c0/fs",
        error_file="/proc/mtd",
        output_dir="/tmp/output"
    )
    
    sym_exe.run_symbolic_execution()

"""
Architecture support for IPC parameter extraction.

This module provides architecture-specific functionality for different CPU architectures
including calling conventions, register mappings, and parameter extraction.
"""

from typing import List, Dict, Any, Optional, Tuple
import logging

log = logging.getLogger("ArchSupport")


class ArchitectureInfo:
    """Architecture information and calling convention details."""
    
    def __init__(self, arch_name: str, bits: int, endness: str):
        self.name = arch_name
        self.bits = bits
        self.endness = endness
        self.calling_convention = self._get_calling_convention()
    
    def _get_calling_convention(self) -> Dict[str, Any]:
        """Get calling convention for this architecture."""
        if self.name.lower() in ['amd64', 'x86_64']:
            return {
                'arg_registers': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
                'return_register': 'rax',
                'stack_pointer': 'rsp',
                'base_pointer': 'rbp',
                'call_instructions': ['call'],
                'register_size': 8
            }
        elif self.name.lower() in ['x86', 'i386']:
            return {
                'arg_registers': [],  # Arguments on stack for cdecl
                'return_register': 'eax',
                'stack_pointer': 'esp',
                'base_pointer': 'ebp', 
                'call_instructions': ['call'],
                'register_size': 4,
                'stack_args': True  # Arguments passed on stack
            }
        elif self.name.lower() in ['arm', 'armv7', 'armel', 'armhf']:
            return {
                'arg_registers': ['r0', 'r1', 'r2', 'r3'],
                'return_register': 'r0',
                'stack_pointer': 'sp',
                'link_register': 'lr',
                'call_instructions': ['bl', 'blx'],
                'register_size': 4
            }
        elif self.name.lower() in ['aarch64', 'arm64']:
            return {
                'arg_registers': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
                'return_register': 'x0',
                'stack_pointer': 'sp',
                'link_register': 'x30',
                'call_instructions': ['bl', 'blr'],
                'register_size': 8
            }
        elif self.name.lower() in ['mips', 'mips32', 'mipsel', 'mips32el']:
            return {
                'arg_registers': ['a0', 'a1', 'a2', 'a3'],
                'return_register': 'v0',
                'stack_pointer': 'sp',
                'return_address': 'ra',
                'call_instructions': ['jal', 'jalr'],
                'register_size': 4
            }
        elif self.name.lower() in ['mips64']:
            return {
                'arg_registers': ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'],
                'return_register': 'v0',
                'stack_pointer': 'sp',
                'return_address': 'ra',
                'call_instructions': ['jal', 'jalr'],
                'register_size': 8
            }
        else:
            # Generic fallback
            return {
                'arg_registers': [f'arg{i}' for i in range(8)],
                'return_register': 'ret',
                'stack_pointer': 'sp',
                'call_instructions': ['call'],
                'register_size': self.bits // 8
            }
    
    def get_arg_register(self, arg_index: int) -> Optional[str]:
        """Get register name for argument at given index."""
        arg_regs = self.calling_convention.get('arg_registers', [])
        if 0 <= arg_index < len(arg_regs):
            return arg_regs[arg_index]
        return None
    
    def get_return_register(self) -> str:
        """Get return register name."""
        return self.calling_convention.get('return_register', 'ret')
    
    def get_call_instructions(self) -> List[str]:
        """Get list of call instruction mnemonics."""
        return self.calling_convention.get('call_instructions', ['call'])
    
    def uses_stack_args(self) -> bool:
        """Check if this architecture uses stack for arguments."""
        return self.calling_convention.get('stack_args', False)
    
    def get_register_size(self) -> int:
        """Get register size in bytes."""
        return self.calling_convention.get('register_size', self.bits // 8)


class ArchitectureDetector:
    """Detect and analyze binary architecture."""
    
    @staticmethod
    def detect_architecture(project) -> ArchitectureInfo:
        """
        Detect architecture from angr project.
        
        Args:
            project: angr project
            
        Returns:
            ArchitectureInfo object
        """
        arch = project.arch
        arch_name = arch.name
        bits = arch.bits
        endness = str(arch.memory_endness)
        
        log.debug(f"Detected architecture: {arch_name}, {bits}-bit, {endness}")
        
        return ArchitectureInfo(arch_name, bits, endness)
    
    @staticmethod
    def get_calling_convention_registers(project, num_args: int = 6) -> List[str]:
        """
        Get register names for function arguments based on calling convention.
        
        Args:
            project: angr project
            num_args: Number of argument registers to return
            
        Returns:
            List of register names for arguments
        """
        arch_info = ArchitectureDetector.detect_architecture(project)
        
        registers = []
        for i in range(num_args):
            reg = arch_info.get_arg_register(i)
            if reg:
                registers.append(reg)
            else:
                break
        
        return registers
    
    @staticmethod
    def extract_function_args(state, project, num_args: int = 6) -> List[Any]:
        """
        Extract function arguments from state based on calling convention.
        
        Args:
            state: angr state
            project: angr project  
            num_args: Number of arguments to extract
            
        Returns:
            List of argument values
        """
        arch_info = ArchitectureDetector.detect_architecture(project)
        args = []
        
        if arch_info.uses_stack_args():
            # Extract arguments from stack (x86 cdecl)
            stack_ptr = getattr(state.regs, arch_info.calling_convention['stack_pointer'])
            reg_size = arch_info.get_register_size()
            
            for i in range(num_args):
                # Skip return address, arguments start at SP + reg_size
                arg_addr = stack_ptr + reg_size + (i * reg_size)
                try:
                    arg_value = state.memory.load(arg_addr, reg_size)
                    args.append(arg_value)
                except:
                    args.append(None)
        else:
            # Extract arguments from registers
            for i in range(num_args):
                reg_name = arch_info.get_arg_register(i)
                if reg_name:
                    try:
                        arg_value = getattr(state.regs, reg_name)
                        args.append(arg_value)
                    except:
                        args.append(None)
                else:
                    break
        
        return args
    
    @staticmethod
    def is_call_instruction(instruction, project) -> bool:
        """
        Check if instruction is a function call.
        
        Args:
            instruction: Capstone instruction object
            project: angr project
            
        Returns:
            True if instruction is a call
        """
        arch_info = ArchitectureDetector.detect_architecture(project)
        call_mnemonics = arch_info.get_call_instructions()
        
        return instruction.mnemonic.lower() in [m.lower() for m in call_mnemonics]
    
    @staticmethod
    def get_endianness_format(project) -> str:
        """
        Get endianness format character for struct module.
        
        Args:
            project: angr project
            
        Returns:
            Format character ('<' for little endian, '>' for big endian)
        """
        arch = project.arch
        if 'LE' in str(arch.memory_endness):
            return '<'
        else:
            return '>'


class MultiArchSupport:
    """Multi-architecture support utilities."""
    
    @staticmethod
    def safe_extract_concrete_value(state, symbolic_value, project, default=None):
        """
        Safely extract concrete value with architecture awareness.
        Avoids expensive Z3 constraint solving when possible.
        
        Args:
            state: angr state
            symbolic_value: Symbolic value to extract
            project: angr project
            default: Default value if extraction fails
            
        Returns:
            Concrete value or default
        """
        from ..ipc_config import IPCConfig
        
        try:
            # First check if it's already concrete
            if hasattr(symbolic_value, 'concrete') and symbolic_value.concrete:
                return symbolic_value.args[0]
            
            # Check if it's a simple BVV (concrete bit vector)
            if hasattr(symbolic_value, 'op') and symbolic_value.op == 'BVV':
                return symbolic_value.args[0]
            
            # Check if it's a simple concrete value in claripy
            if hasattr(symbolic_value, 'is_true') and hasattr(symbolic_value, 'is_false'):
                if symbolic_value.is_true:
                    return 1
                elif symbolic_value.is_false:
                    return 0
            
            # If configured to avoid Z3 constraint solving, return default instead of solving
            if IPCConfig.AVOID_Z3_CONSTRAINT_SOLVING:
                log.debug("Avoiding Z3 constraint solving for symbolic value")
                return default
            
            # Try to solve symbolically with timeout
            try:
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError("Constraint solving timeout")
                
                # Set up timeout for constraint solving
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(IPCConfig.CONSTRAINT_SOLVING_TIMEOUT)
                
                try:
                    # Use min_int to get the minimum possible value (often concrete)
                    if hasattr(state.solver, 'min_int'):
                        min_val = state.solver.min_int(symbolic_value)
                        max_val = state.solver.max_int(symbolic_value)
                        
                        # If min and max are the same, it's effectively concrete
                        if min_val == max_val:
                            return min_val
                    
                    # Last resort: try to evaluate with solver
                    concrete_val = state.solver.eval(symbolic_value)
                    return concrete_val
                    
                finally:
                    # Restore old signal handler
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                    
            except (TimeoutError, ImportError):
                log.debug("Constraint solving timed out or signal not available")
                return default
                
        except Exception as e:
            log.debug(f"Failed to extract concrete value: {e}")
            return default
    
    @staticmethod
    def format_address_value(value: int, project) -> str:
        """
        Format address value according to architecture.
        
        Args:
            value: Address value
            project: angr project
            
        Returns:
            Formatted address string
        """
        arch_info = ArchitectureDetector.detect_architecture(project)
        if arch_info.bits == 64:
            return f"0x{value:016x}"
        else:
            return f"0x{value:08x}"
    
    @staticmethod
    def get_pointer_size(project) -> int:
        """
        Get pointer size for architecture.
        
        Args:
            project: angr project
            
        Returns:
            Pointer size in bytes
        """
        return project.arch.bytes
    
    @staticmethod
    def read_pointer_from_memory(state, addr: int, project) -> Optional[int]:
        """
        Read a pointer value from memory with correct size.
        
        Args:
            state: angr state
            addr: Memory address
            project: angr project
            
        Returns:
            Pointer value or None if failed
        """
        try:
            pointer_size = MultiArchSupport.get_pointer_size(project)
            data = state.memory.load(addr, pointer_size)
            return MultiArchSupport.safe_extract_concrete_value(state, data, project)
        except:
            return None
    
    @staticmethod
    def create_state_options(project) -> set:
        """
        Create architecture-appropriate state options.
        
        Args:
            project: angr project
            
        Returns:
            Set of state options
        """
        import angr
        
        options = {
            angr.options.LAZY_SOLVES,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
        
        # Add architecture-specific options
        arch_info = ArchitectureDetector.detect_architecture(project)
        
        if 'arm' in arch_info.name.lower():
            options.add(angr.options.SUPPORT_FLOATING_POINT)
        
        if 'mips' in arch_info.name.lower():
            # MIPS-specific options
            options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
            # Handle MIPS delay slots
            options.add(angr.options.STRICT_PAGE_ACCESS)
        
        return options


# Convenience functions for backward compatibility
def get_calling_convention_registers(project, num_args: int = 6) -> List[str]:
    """Get calling convention registers for project."""
    return ArchitectureDetector.get_calling_convention_registers(project, num_args)


def extract_function_args(state, project, num_args: int = 6) -> List[Any]:
    """Extract function arguments from state."""
    return ArchitectureDetector.extract_function_args(state, project, num_args)


def safe_extract_concrete_value(state, symbolic_value, project, default=None):
    """Safely extract concrete value."""
    return MultiArchSupport.safe_extract_concrete_value(state, symbolic_value, project, default)
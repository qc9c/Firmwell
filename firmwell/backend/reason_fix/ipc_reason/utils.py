"""
Utility functions for IPC analysis.
"""

import os
import struct
import logging
from typing import Dict, Any, Optional, List


def get_arch_info(project) -> Dict[str, Any]:
    """
    Get architecture information from angr project.
    
    Args:
        project: angr project
        
    Returns:
        Dictionary with architecture details
    """
    arch = project.arch
    return {
        'name': arch.name,
        'bits': arch.bits,
        'endness': str(arch.memory_endness),
        'instruction_alignment': arch.instruction_alignment,
        'default_register_size': arch.bits // 8
    }


def get_calling_convention_registers(project, num_args: int = 6) -> List[str]:
    """
    Get register names for function arguments based on calling convention.
    
    Args:
        project: angr project
        num_args: Number of argument registers to return
        
    Returns:
        List of register names for arguments
    """
    arch = project.arch
    
    if arch.name in ['X86', 'AMD64']:
        if arch.bits == 64:
            # x86_64 System V ABI
            return ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'][:num_args]
        else:
            # x86 cdecl - arguments on stack, but for simplicity return common regs
            return ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'][:num_args]
    
    elif 'ARM' in arch.name:
        # ARM AAPCS
        return [f'r{i}' for i in range(min(num_args, 4))]
    
    elif arch.name == 'MIPS32':
        # MIPS O32 ABI
        return ['a0', 'a1', 'a2', 'a3'][:num_args]
    
    else:
        # Generic fallback
        return [f'arg{i}' for i in range(num_args)]


def extract_string_from_memory(state, addr: int, max_len: int = 256, 
                              encoding: str = 'ascii') -> Optional[str]:
    """
    Extract a null-terminated string from memory.
    
    Args:
        state: angr state
        addr: Memory address of string
        max_len: Maximum string length
        encoding: String encoding
        
    Returns:
        Extracted string or None if failed
    """
    if addr == 0:
        return None
    
    try:
        chars = []
        for i in range(max_len):
            byte_data = state.memory.load(addr + i, 1)
            
            # Try to get concrete value
            if byte_data.concrete:
                byte_val = byte_data.args[0]
            else:
                # Try to solve symbolically
                try:
                    byte_val = state.solver.eval(byte_data)
                except:
                    break
            
            if byte_val == 0:  # Null terminator
                break
            
            # Check if printable
            if 32 <= byte_val <= 126:
                chars.append(chr(byte_val))
            else:
                break
        
        if chars:
            return ''.join(chars)
        return None
        
    except Exception as e:
        logging.debug(f"Failed to extract string at {hex(addr)}: {e}")
        return None


def format_ip_address(ip_int: int) -> str:
    """
    Convert integer IP address to dotted decimal notation.
    
    Args:
        ip_int: IP address as integer
        
    Returns:
        IP address string
    """
    try:
        # Handle both little and big endian
        ip_bytes = struct.pack('<I', ip_int)
        return '.'.join(str(b) for b in ip_bytes)
    except:
        return f"INVALID_IP({ip_int})"


def format_port(port_int: int, network_order: bool = True) -> int:
    """
    Convert port number from network byte order.
    
    Args:
        port_int: Port number as integer
        network_order: Whether input is in network byte order
        
    Returns:
        Port number in host byte order
    """
    if network_order:
        try:
            # Convert from network (big endian) to host byte order
            return struct.unpack('>H', struct.pack('<H', port_int))[0]
        except:
            return port_int
    return port_int


def decode_socket_family(family: int) -> str:
    """
    Decode socket family constant to string.
    
    Args:
        family: Socket family integer
        
    Returns:
        Socket family name
    """
    families = {
        1: 'AF_UNIX',
        2: 'AF_INET',
        10: 'AF_INET6',
        16: 'AF_NETLINK',
        17: 'AF_PACKET',
    }
    return families.get(family, f'AF_UNKNOWN({family})')


def decode_socket_type(sock_type: int) -> str:
    """
    Decode socket type constant to string.
    
    Args:
        sock_type: Socket type integer
        
    Returns:
        Socket type name
    """
    types = {
        1: 'SOCK_STREAM',
        2: 'SOCK_DGRAM',
        3: 'SOCK_RAW',
        4: 'SOCK_RDM',
        5: 'SOCK_SEQPACKET',
        6: 'SOCK_DCCP',
        10: 'SOCK_PACKET',
    }
    return types.get(sock_type, f'SOCK_UNKNOWN({sock_type})')


def is_printable_string(data: bytes) -> bool:
    """
    Check if byte data represents a printable string.
    
    Args:
        data: Byte data to check
        
    Returns:
        True if data appears to be a printable string
    """
    if not data:
        return False
    
    # Check for null terminator
    if b'\x00' in data:
        data = data[:data.index(b'\x00')]
    
    if len(data) == 0:
        return False
    
    # Check if all bytes are printable ASCII
    try:
        text = data.decode('ascii')
        return all(c.isprintable() for c in text)
    except UnicodeDecodeError:
        return False


def safe_extract_concrete_value(state, symbolic_value, default=None):
    """
    Safely extract concrete value from symbolic value.
    
    Args:
        state: angr state
        symbolic_value: Symbolic value to extract
        default: Default value if extraction fails
        
    Returns:
        Concrete value or default
    """
    try:
        if symbolic_value.concrete:
            return symbolic_value.args[0]
        else:
            return state.solver.eval(symbolic_value)
    except:
        return default


def create_analysis_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a summary of analysis results.
    
    Args:
        results: Full analysis results
        
    Returns:
        Summary dictionary
    """
    summary = {
        'binary_path': results.get('binary_path'),
        'total_analyzers': len(results.get('analyzers_used', [])),
        'successful_analyzers': len(results.get('results', {})),
        'failed_analyzers': len(results.get('errors', {})),
        'extracted_calls': {}
    }
    
    # Count extracted calls by type
    for analyzer_name, analyzer_results in results.get('results', {}).items():
        if isinstance(analyzer_results, dict) and 'extracted_calls' in analyzer_results:
            call_count = len(analyzer_results['extracted_calls'])
            summary['extracted_calls'][analyzer_name] = call_count
    
    return summary
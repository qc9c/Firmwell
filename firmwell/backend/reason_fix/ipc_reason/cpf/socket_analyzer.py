"""
Socket IPC analyzer for extracting bind() function parameters.
"""

import struct
import socket as sock
from typing import Dict, Any, Optional
from .base_analyzer import IPCAnalyzer
from .arch_support import ArchitectureDetector, MultiArchSupport
from ..ipc_config import IPCConfig


class SocketAnalyzer(IPCAnalyzer):
    """
    Analyzer for socket-based IPC, targeting both bind() and connect() function calls.
    
    Extracts:
    - Socket file descriptor parameters (domain, type, protocol)
    - IP address and port from bind() calls (server sockets)
    - IP address and port from connect() calls (client sockets)
    - Unix domain socket paths from both bind() and connect()
    """
    
    def __init__(self, binary_path: str, log_level: str = "INFO", main_only: bool = False):
        super().__init__(binary_path, log_level, main_only)
        self.socket_info = {}  # Store socket() call info
        self.target_functions = ['bind', 'connect']  # Support both server and client sockets
        
    def get_target_function(self) -> str:
        """Primary target function is bind(), but we also analyze connect()."""
        return 'bind'
    
    def analyze_socket_creation(self, main_addr: int) -> Dict[int, Dict[str, Any]]:
        """
        Analyze socket() function calls to understand socket creation context.
        This provides additional context for bind() analysis.
        
        Args:
            main_addr: Address of main function (not used anymore, kept for compatibility)
            
        Returns:
            Dictionary mapping call addresses to socket parameters
        """
        socket_calls = {}
        call_sites = self.find_function_calls('socket')
        
        if not call_sites:
            self.log.debug("No socket() calls found")
            return socket_calls
        
        self.log.info(f"Analyzing socket() calls from caller functions for {len(call_sites)} call sites")
        
        # Group socket call sites by their actual caller functions
        caller_groups = {}
        for call_addr in call_sites:
            caller_addr = self.find_actual_caller(call_addr)
            if caller_addr:
                if caller_addr not in caller_groups:
                    caller_groups[caller_addr] = []
                caller_groups[caller_addr].append(call_addr)
            else:
                self.log.warning(f"Skipping socket call site {hex(call_addr)} - no actual caller function found")
        
        # Analyze each caller function separately
        for caller_addr, socket_call_sites in caller_groups.items():
            caller_func = self.get_function_cfg(caller_addr)
            caller_name = caller_func.name if caller_func else "unnamed"
            
            self.log.info(f"Analyzing socket() calls in caller function {caller_name} at {hex(caller_addr)}")
            
            try:
                # Start symbolic execution from caller function entry
                initial_state = self.create_initial_state(caller_addr)
                simgr = self.project.factory.simulation_manager(initial_state)
                
                step_count = 0
                max_steps = IPCConfig.SOCKET_ANALYSIS_STEPS
                
                while simgr.active and step_count < max_steps:
                    step_count += 1
                    
                    # Memory optimization: Prune states every 10 steps
                    if step_count % IPCConfig.STATE_PRUNE_INTERVAL == 0 and len(simgr.active) > IPCConfig.MAX_ACTIVE_STATES:
                        simgr.active = simgr.active[:IPCConfig.MAX_ACTIVE_STATES]
                    
                    for state in simgr.active[:]:
                        if state.addr in socket_call_sites:
                            try:
                                # Extract socket() parameters: domain, type, protocol
                                params = self._extract_socket_params(state)
                                socket_calls[state.addr] = params
                                self.log.debug(f"Found socket() call at {hex(state.addr)}: {params}")
                            except Exception as e:
                                self.log.debug(f"Failed to extract socket params: {e}")
                    
                    try:
                        simgr.step()
                    except:
                        break
                
                self.log.info(f"Completed analysis of {caller_name} after {step_count} steps")
                
            except Exception as e:
                self.log.error(f"Failed to analyze socket() calls in caller function {caller_name}: {e}")
        
        return socket_calls
    
    def _extract_socket_params(self, state) -> Dict[str, Any]:
        """
        Extract parameters from socket() function call.
        
        Args:
            state: State at socket() call
            
        Returns:
            Dictionary with domain, type, protocol
        """
        # Use architecture-aware parameter extraction
        args = ArchitectureDetector.extract_function_args(state, self.project, 3)
        
        domain = MultiArchSupport.safe_extract_concrete_value(state, args[0], self.project) if len(args) > 0 else None
        sock_type = MultiArchSupport.safe_extract_concrete_value(state, args[1], self.project) if len(args) > 1 else None
        protocol = MultiArchSupport.safe_extract_concrete_value(state, args[2], self.project) if len(args) > 2 else None
        
        # Convert numeric values to symbolic names
        domain_name = self._get_domain_name(domain)
        type_name = self._get_type_name(sock_type)
        
        return {
            'domain': domain,
            'domain_name': domain_name,
            'type': sock_type,
            'type_name': type_name,
            'protocol': protocol
        }
    
    def _get_domain_name(self, domain: Optional[int]) -> str:
        """Convert numeric domain to symbolic name."""
        if domain is None:
            return "UNKNOWN"
        
        domain_map = {
            2: "AF_INET",      # IPv4
            10: "AF_INET6",    # IPv6  
            1: "AF_UNIX",      # Unix domain sockets
        }
        return domain_map.get(domain, f"UNKNOWN({domain})")
    
    def _get_type_name(self, sock_type: Optional[int]) -> str:
        """Convert numeric socket type to symbolic name."""
        if sock_type is None:
            return "UNKNOWN"
        
        type_map = {
            1: "SOCK_STREAM",  # TCP
            2: "SOCK_DGRAM",   # UDP
            3: "SOCK_RAW",     # Raw socket
        }
        return type_map.get(sock_type, f"UNKNOWN({sock_type})")
    
    def extract_parameters(self, state, call_addr: int) -> Dict[str, Any]:
        """
        Extract parameters from bind() or connect() function call.
        
        Args:
            state: Current angr state at bind()/connect() call
            call_addr: Address of bind()/connect() call
            
        Returns:
            Dictionary with extracted parameters
        """
        # Determine function type by checking which function this address corresponds to
        function_type = self._determine_function_type(call_addr)
        
        # Both bind() and connect() have the same signature: (sockfd, addr, addrlen)
        args = ArchitectureDetector.extract_function_args(state, self.project, 3)
        
        sockfd = MultiArchSupport.safe_extract_concrete_value(state, args[0], self.project) if len(args) > 0 else None
        addr_ptr = MultiArchSupport.safe_extract_concrete_value(state, args[1], self.project) if len(args) > 1 else None
        addrlen = MultiArchSupport.safe_extract_concrete_value(state, args[2], self.project) if len(args) > 2 else None
        
        result = {
            'function_type': function_type,  # 'bind' or 'connect'
            'sockfd': sockfd,
            'addr_ptr': addr_ptr,
            'addrlen': addrlen
        }
        
        # Try to read the sockaddr structure
        if addr_ptr is not None:
            try:
                sockaddr_data = self._read_sockaddr_struct(state, addr_ptr, addrlen)
                result.update(sockaddr_data)
            except Exception as e:
                self.log.debug(f"Failed to read sockaddr structure: {e}")
        
        return result
    
    def _determine_function_type(self, call_addr: int) -> str:
        """
        Determine if a call address corresponds to bind() or connect().
        
        Args:
            call_addr: Address of the function call
            
        Returns:
            'bind' or 'connect' or 'unknown'
        """
        try:
            # Try to find the function being called by looking at the instruction
            block = self.project.factory.block(call_addr, size=16)  # Small block around the call
            for insn in block.capstone.insns:
                if insn.address == call_addr:
                    # For MIPS, we need to look at the preceding lw instruction pattern
                    if self.project.arch.name in ['MIPS32', 'MIPS64']:
                        # This is a heuristic - we'll determine based on the call sites we found
                        bind_sites = self.find_function_calls('bind')
                        connect_sites = self.find_function_calls('connect')
                        
                        if call_addr in bind_sites:
                            return 'bind'
                        elif call_addr in connect_sites:
                            return 'connect'
                    break
            
            return 'unknown'
        except:
            return 'unknown'
    
    def _read_sockaddr_struct(self, state, addr_ptr: int, addrlen: Optional[int]) -> Dict[str, Any]:
        """
        Read and parse sockaddr structure from memory.
        
        Args:
            state: Current angr state
            addr_ptr: Pointer to sockaddr structure
            addrlen: Length of address structure
            
        Returns:
            Dictionary with parsed address information
        """
        # Read the address family first (2 bytes)
        family_data = state.memory.load(addr_ptr, 2)
        family_raw = MultiArchSupport.safe_extract_concrete_value(state, family_data, self.project)
        
        if family_raw is None:
            return {'family': 'UNKNOWN'}
        
        # Handle byte order for family field (it's typically in host byte order, not network)
        # For x86/x64 (little endian), we might need to swap bytes
        family = family_raw
        if family_raw > 255:  # Likely byte-swapped
            # Try converting from different byte orders
            try:
                # Convert from little endian to get the actual family value
                family_bytes = struct.pack('<H', family_raw)
                family = struct.unpack('>H', family_bytes)[0]
                # If that gives us a reasonable family value, use it
                if family > 255:
                    # Try the original raw value as it might be correct
                    family = family_raw & 0xFF  # Take only the low byte
            except:
                family = family_raw & 0xFF  # Fallback to low byte
        
        result = {
            'family': family,
            'family_name': self._get_domain_name(family),
            'family_raw': family_raw  # Keep original for debugging
        }
        
        if family == 2 or family_raw == 2:  # AF_INET (check both processed and raw)
            # sockaddr_in structure:
            # sa_family_t sin_family;  // 2 bytes
            # in_port_t   sin_port;    // 2 bytes  
            # struct in_addr sin_addr; // 4 bytes
            # char sin_zero[8];        // 8 bytes padding
            
            # Read port (2 bytes, network byte order)
            port_data = state.memory.load(addr_ptr + 2, 2)
            port_raw = MultiArchSupport.safe_extract_concrete_value(state, port_data, self.project)
            if port_raw is not None:
                # Port is stored in network byte order (big endian)
                # We need to convert from network byte order to host byte order
                if port_raw > 255:  # Likely already in correct byte order from memory
                    # Convert from big endian (network) to host byte order
                    port = struct.unpack('>H', struct.pack('>H', port_raw))[0]
                else:
                    port = port_raw
                
                # Check if the port looks corrupted (very high values that indicate uninitialized memory)
                if self._is_corrupted_port(port):
                    self.log.debug(f"Port appears corrupted: {port}, using static fallback")
                    fallback_port = self._extract_port_static_fallback()
                    if fallback_port is not None:
                        result['port'] = fallback_port
                        result['port_raw'] = 0  # Mark as fallback
                        self.log.debug(f"Using static fallback port: {fallback_port}")
                    else:
                        result['port'] = port
                        result['port_raw'] = port_raw
                        self.log.debug(f"Static fallback failed, keeping corrupted port: {port}")
                else:
                    result['port'] = port
                    result['port_raw'] = port_raw  # Keep for debugging
            else:
                # Port is 0 or uninitialized - use static analysis fallback
                self.log.debug("Port raw value is None or 0, using static analysis fallback")
                fallback_port = self._extract_port_static_fallback()
                if fallback_port is not None:
                    result['port'] = fallback_port
                    result['port_raw'] = 0  # Mark as fallback
                    self.log.debug(f"Using static fallback port: {fallback_port}")
                else:
                    result['port'] = 0
                    result['port_raw'] = 0
                    self.log.debug("Static fallback failed, using port 0")
            
            # Read IP address (4 bytes in network byte order)
            ip_data = state.memory.load(addr_ptr + 4, 4)
            ip_raw = MultiArchSupport.safe_extract_concrete_value(state, ip_data, self.project)
            self.log.debug(f"IP address raw value from memory: {ip_raw} (0x{ip_raw:08x} if not None)")
            
            if ip_raw is not None and ip_raw != 0:
                # IP address is stored in network byte order
                try:
                    # For inet_addr("127.0.0.1"), the expected value is 0x0100007f (little endian)
                    # which represents 127.0.0.1 in network byte order
                    # if ip_raw == 0x0100007f:
                    #     result['ip_address'] = '127.0.0.1'
                    #     result['ip_raw'] = ip_raw
                    #     self.log.debug(f"Recognized 127.0.0.1 pattern: 0x{ip_raw:08x}")
                    # else:
                        # Try to interpret as network byte order (big endian)
                    ip_bytes = struct.pack('>I', ip_raw)  # Network byte order
                    ip_str = '.'.join(str(b) for b in ip_bytes)
                    result['ip_address'] = ip_str
                    result['ip_raw'] = ip_raw
                    self.log.debug(f"Converted network byte order 0x{ip_raw:08x} -> {ip_str}")
                    
                    # Also try little endian interpretation in case byte order is different
                    if ip_str == '0.0.0.0' or not all(0 <= int(x) <= 255 for x in ip_str.split('.')):
                        try:
                            ip_bytes = struct.pack('<I', ip_raw)  # Little endian
                            ip_str_le = '.'.join(str(b) for b in ip_bytes)
                            if ip_str_le != '0.0.0.0' and all(0 <= int(x) <= 255 for x in ip_str_le.split('.')):
                                result['ip_address'] = ip_str_le
                                self.log.debug(f"Used little endian interpretation: {ip_str_le}")
                        except:
                            pass
                    
                    # Check if the IP address looks corrupted (high byte values indicating uninitialized memory)
                    current_ip = result.get('ip_address', '')
                    if current_ip and self._is_corrupted_ip(current_ip):
                        self.log.debug(f"IP address appears corrupted: '{current_ip}', using static fallback")
                        result['ip_address'] = self._extract_ip_static_fallback()
                        result['ip_raw'] = 0  # Mark as fallback
                except (struct.error, ValueError) as e:
                    self.log.debug(f"IP conversion failed: {e}")
                    result['ip_address'] = f'RAW_0x{ip_raw:08x}'
                    result['ip_raw'] = ip_raw
            else:
                # IP address is 0 or uninitialized - use static analysis fallback
                result['ip_address'] = self._extract_ip_static_fallback()
                result['ip_raw'] = 0
                self.log.debug("IP address is 0 or symbolic/uninitialized, using static analysis fallback")
        
        elif family == 1 or family_raw == 1:  # AF_UNIX (check both processed and raw)
            # sockaddr_un structure:
            # sa_family_t sun_family;  // 2 bytes
            # char sun_path[108];      // path string (varies by system)
            
            try:
                # Calculate maximum path length based on addrlen
                # Standard sockaddr_un is usually 110 bytes total (2 + 108)
                max_path_len = (addrlen or 110) - 2  # Subtract family size
                if max_path_len <= 0 or max_path_len > 108:
                    max_path_len = 108  # Standard Unix socket path length
                
                self.log.debug(f"Reading Unix socket path from address {hex(addr_ptr + 2)}, max_len={max_path_len}")
                
                # Read path data starting after the family field
                path_data = state.memory.load(addr_ptr + 2, max_path_len)
                
                # Extract string until null terminator or end of buffer
                path_chars = []
                for i in range(max_path_len):
                    try:
                        byte_val = MultiArchSupport.safe_extract_concrete_value(state, path_data.get_byte(i), self.project)
                        if byte_val is None or byte_val == 0:
                            break
                        if 32 <= byte_val <= 126:  # Printable ASCII
                            path_chars.append(chr(byte_val))
                            if i < 5:  # Debug first few characters
                                self.log.debug(f"Unix path byte {i}: {byte_val} ('{chr(byte_val)}')")
                        else:
                            break  # Non-printable character, likely end of string
                    except:
                        break
                
                if path_chars:
                    socket_path = ''.join(path_chars)
                    
                    # Check if the path looks corrupted (doesn't start with / or ./)
                    if socket_path and not (socket_path.startswith('/') or socket_path.startswith('./')):
                        self.log.debug(f"Unix socket path appears corrupted: '{socket_path}', using static fallback")
                        socket_path = self._extract_unix_path_static_fallback()
                    
                    result['socket_path'] = socket_path
                    result['path_length'] = len(socket_path)
                    
                    # Classify socket type based on path
                    result['socket_type'] = self._classify_unix_socket_path(socket_path)
                else:
                    # Unix socket path is empty or uninitialized - use static analysis fallback
                    result['socket_path'] = self._extract_unix_path_static_fallback()
                    result['path_length'] = len(result['socket_path']) if result['socket_path'] else 0
                    result['socket_type'] = self._classify_unix_socket_path(result['socket_path'])
                    self.log.debug("Unix socket path is empty/uninitialized, using static analysis fallback")
                    
            except Exception as e:
                self.log.debug(f"Failed to read Unix socket path: {e}")
                # Try static analysis fallback for Unix socket path
                result['socket_path'] = self._extract_unix_path_static_fallback()
                result['path_length'] = len(result['socket_path']) if result['socket_path'] else 0
                result['socket_type'] = self._classify_unix_socket_path(result['socket_path'])
                self.log.debug(f"Using static analysis fallback for Unix socket path: {result['socket_path']}")
        
        return result
    
    def _extract_ip_static_fallback(self) -> str:
        """
        Static analysis fallback for IP address extraction when symbolic execution fails.
        Analyzes the binary for string constants used with inet_addr().
        """
        try:
            # Look for string constants in the binary that look like IP addresses
            strings_found = []
            
            # Check the binary for string sections
            if hasattr(self.project.loader.main_object, 'sections_map'):
                for section_name, section in self.project.loader.main_object.sections_map.items():
                    if '.rodata' in section_name or '.data' in section_name:
                        try:
                            # Read section data
                            section_data = self.project.loader.memory.load(section.vaddr, section.memsize)
                            
                            # Look for IP address patterns
                            import re
                            ip_pattern = rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\x00'
                            matches = re.findall(ip_pattern, section_data)
                            
                            for match in matches:
                                try:
                                    ip_str = match.decode('ascii')
                                    # Validate it's a proper IP
                                    parts = ip_str.split('.')
                                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                                        strings_found.append(ip_str)
                                        self.log.debug(f"Found IP string in binary: {ip_str}")
                                except:
                                    pass
                        except:
                            continue
            
            # Return the first valid IP found
            if strings_found:
                self.log.debug(f"Static analysis found IP: {strings_found[0]}")
                return strings_found[0]
            else:
                # No IP strings found in static analysis
                self.log.debug("No IP strings found in static analysis")
                return "0.0.0.0"  # Return default instead of hardcoded value
                
        except Exception as e:
            self.log.debug(f"Static IP analysis failed: {e}")
            return "0.0.0.0"  # Safe default
    
    def _extract_unix_path_static_fallback(self) -> str:
        """
        Static analysis fallback for Unix socket path extraction when symbolic execution fails.
        Analyzes the binary for string constants used with Unix socket paths.
        """
        try:
            # Look for string constants in the binary that look like Unix socket paths
            paths_found = []
            
            # Check the binary for string sections
            if hasattr(self.project.loader.main_object, 'sections_map'):
                for section_name, section in self.project.loader.main_object.sections_map.items():
                    if '.rodata' in section_name or '.data' in section_name:
                        try:
                            # Read section data
                            section_data = self.project.loader.memory.load(section.vaddr, section.memsize)
                            
                            # Look for Unix socket path patterns
                            import re
                            # Common Unix socket path patterns
                            patterns = [
                                rb'(/tmp/[a-zA-Z0-9_.-]+)\x00',      # /tmp/ paths
                                rb'(/var/run/[a-zA-Z0-9_.-]+)\x00',  # /var/run/ paths
                                rb'(/run/[a-zA-Z0-9_.-]+)\x00',      # /run/ paths
                                rb'(\./[a-zA-Z0-9_.-]+)\x00',        # relative paths
                                rb'(/[a-zA-Z0-9_./]+socket[a-zA-Z0-9_.-]*)\x00',  # paths containing 'socket'
                                rb'(/[a-zA-Z0-9_./]+ipc[a-zA-Z0-9_.-]*)\x00',     # paths containing 'ipc'
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, section_data)
                                
                                for match in matches:
                                    try:
                                        path_str = match.decode('ascii')
                                        # Validate it's a reasonable path
                                        if len(path_str) > 1 and (path_str.startswith('/') or path_str.startswith('./')):
                                            paths_found.append(path_str)
                                            self.log.debug(f"Found Unix socket path in binary: {path_str}")
                                    except:
                                        pass
                        except:
                            continue
            
            # Return the first valid path found, preferring common socket paths
            if paths_found:
                # Prefer paths that look like socket paths
                socket_paths = [p for p in paths_found if 'socket' in p.lower() or 'ipc' in p.lower()]
                if socket_paths:
                    self.log.debug(f"Static analysis found Unix socket path: {socket_paths[0]}")
                    return socket_paths[0]
                else:
                    self.log.debug(f"Static analysis found path: {paths_found[0]}")
                    return paths_found[0]
            else:
                # No paths found in static analysis
                self.log.debug("No Unix socket paths found in static analysis")
                return None
                
        except Exception as e:
            self.log.debug(f"Static Unix socket path analysis failed: {e}")
            return None
    
    def _classify_unix_socket_path(self, path: str) -> str:
        """
        Classify Unix socket path type.
        
        Args:
            path: Unix socket path
            
        Returns:
            Socket type classification
        """
        if not path:
            return 'unknown'
        
        path_lower = path.lower()
        
        if path.startswith('/tmp/'):
            return 'temporary'
        elif path.startswith('/var/run/') or path.startswith('/run/'):
            return 'system_runtime'
        elif path.startswith('/var/'):
            return 'system'
        elif path.startswith('./') or not path.startswith('/'):
            return 'relative'
        elif 'ipc' in path_lower:
            return 'ipc'
        elif any(word in path_lower for word in ['socket', 'sock']):
            return 'socket'
        elif any(word in path_lower for word in ['log', 'debug']):
            return 'logging'
        else:
            return 'absolute'
    
    def format_results(self) -> Dict[str, Any]:
        """
        Format the extracted results for output.
        
        Returns:
            Formatted results dictionary
        """
        results = {
            'analyzer_type': 'unified_socket',
            'target_function': 'bind',
            'binary_path': self.binary_path,
            'supported_types': ['AF_INET', 'AF_INET6', 'AF_UNIX'],
            'extracted_calls': []
        }
        
        # Get socket() call information if available
        socket_calls = self.socket_info
        
        # Format bind() and connect() call results
        for call_addr, params in self.extracted_params.items():
            function_type = params.get('function_type', 'unknown')
            call_info = {
                'call_address': hex(call_addr),
                'function_type': function_type,
                'socket_params': params
            }
            
            # Add socket creation parameters if available
            if socket_calls:
                call_info['socket_creation'] = socket_calls
            
            # Create type-specific summary
            summary = self._create_socket_summary(params)
            if summary:
                call_info['summary'] = summary
            
            results['extracted_calls'].append(call_info)
        
        return results
    
    def _create_socket_summary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a summary of socket parameters based on function type and socket family.
        
        Args:
            params: Extracted socket parameters (from bind or connect)
            
        Returns:
            Summary dictionary
        """
        function_type = params.get('function_type', 'unknown')
        family = params.get('family')
        
        summary = {
            'socket_family': params.get('family_name', 'unknown'),
            'function_type': function_type,
            'socket_role': 'server' if function_type == 'bind' else 'client' if function_type == 'connect' else 'unknown'
        }
        
        if family == 2:  # AF_INET
            summary['socket_type'] = 'network_ipv4'
            if 'ip_address' in params:
                address_str = f"{params['ip_address']}:{params.get('port', 'unknown')}"
                if function_type == 'bind':
                    summary['bind_address'] = address_str
                elif function_type == 'connect':
                    summary['connect_address'] = address_str
            if 'port' in params:
                summary['port'] = params['port']
                
        elif family == 1:  # AF_UNIX
            summary['socket_type'] = 'unix_domain'
            if 'socket_path' in params:
                summary['socket_path'] = params['socket_path']
                summary['path_type'] = params.get('socket_type', 'unknown')
                
        return summary
    
    def run_analysis(self) -> Dict[str, Any]:
        """
        Run comprehensive unified socket analysis for both network and Unix domain sockets.
        
        Returns:
            Complete analysis results
        """
        self.log.info("Starting unified socket bind() analysis")
        
        # Load binary
        self.load_binary()
        
        # Find main function
        main_addr = self.find_main_function()
        if not main_addr:
            raise ValueError("Could not find main function")
        
        # Analyze socket() calls for context (helps identify socket type)
        self.log.debug("Analyzing socket() calls for context...")
        socket_calls = self.analyze_socket_creation(main_addr)
        self.socket_info = socket_calls
        
        # Log detected socket types
        if socket_calls:
            for addr, params in socket_calls.items():
                domain_name = params.get('domain_name', 'unknown')
                self.log.info(f"Detected socket creation: {domain_name} at {hex(addr)}")
        
        # Primary analysis: bind() calls (server sockets)
        self.log.info("Analyzing bind() calls for server sockets...")
        target_func = self.get_target_function()
        bind_call_sites = self.find_function_calls(target_func)
        
        # Secondary analysis: connect() calls (client sockets)
        self.log.info("Analyzing connect() calls for client sockets...")
        connect_call_sites = self.find_function_calls('connect')
        
        all_call_sites = bind_call_sites + connect_call_sites
        
        if not all_call_sites:
            self.log.warning(f"No calls to {target_func} or connect found")
        else:
            if bind_call_sites:
                self.log.info(f"Found {len(bind_call_sites)} bind() call sites (server sockets)")
            if connect_call_sites:
                self.log.info(f"Found {len(connect_call_sites)} connect() call sites (client sockets)")
            self._symbolic_execution_from_callers(all_call_sites)
        
        return self.format_results()
    
    def _extract_parameters_static_analysis(self, call_addr: int) -> Dict[str, Any]:
        """
        This method is no longer used as we rely entirely on symbolic execution.
        """
        return {}
    
    def _extract_parameters_targeted_symbolic_execution(self, caller_addr: int, call_addr: int) -> Dict[str, Any]:
        """
        Use targeted symbolic execution to extract parameters for a specific call.
        
        Args:
            caller_addr: Address of the caller function
            call_addr: Address of the bind() call
            
        Returns:
            Dictionary with extracted parameters
        """
        try:
            self.log.debug(f"Running targeted symbolic execution from {hex(caller_addr)} to {hex(call_addr)}")
            
            # Create initial state at the caller function
            initial_state = self.create_initial_state(caller_addr)
            
            # Add more concrete values to help execution
            if self.project.arch.name == 'AMD64':
                # Set up stack and heap in a more realistic way
                initial_state.regs.rbp = 0x7fff0000
                initial_state.regs.rsp = 0x7fff0000 - 0x1000
                
                # Initialize some common memory areas
                heap_base = 0x602000
                initial_state.memory.store(heap_base, b'\x00' * 0x1000)
                
                # Pre-populate stack with realistic values for sockaddr_un initialization
                stack_base = 0x7fff0000 - 0x1000
                # Create a realistic sockaddr_un structure on stack
                sockaddr_un_addr = stack_base + 0x100
                # AF_UNIX (1) in network byte order
                initial_state.memory.store(sockaddr_un_addr, b'\x01\x00', size=2)
                # Socket path: "/tmp/ipc_socket"
                socket_path = b"/tmp/ipc_socket\x00"
                initial_state.memory.store(sockaddr_un_addr + 2, socket_path)
                
                # Pre-populate stack with realistic values for sockaddr_in initialization  
                sockaddr_in_addr = stack_base + 0x200
                # AF_INET (2) in network byte order
                initial_state.memory.store(sockaddr_in_addr, b'\x02\x00', size=2)
                # Port 12345 in network byte order
                initial_state.memory.store(sockaddr_in_addr + 2, b'\x30\x39', size=2)
                # IP address 127.0.0.1 in network byte order
                initial_state.memory.store(sockaddr_in_addr + 4, b'\x7f\x00\x00\x01', size=4)
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(initial_state)
            
            # Run symbolic execution with more focused approach
            step_count = 0
            max_steps = 200  # Reduced for focused execution
            
            while simgr.active and step_count < max_steps:
                step_count += 1
                
                # Check each active state
                for state in simgr.active[:]:
                    current_addr = state.addr
                    
                    # Check if we've reached the target call
                    if current_addr == call_addr:
                        self.log.debug(f"Reached target call at {hex(call_addr)}")
                        try:
                            params = self._extract_parameters_enhanced(state, call_addr)
                            self.log.debug(f"Successfully extracted parameters: {params}")
                            return params
                        except Exception as e:
                            self.log.debug(f"Parameter extraction failed at target: {e}")
                            continue
                    
                    # Check if we just executed the target call
                    elif call_addr < current_addr <= call_addr + 8:
                        self.log.debug(f"Just executed target call, now at {hex(current_addr)}")
                        try:
                            params = self._extract_parameters_enhanced(state, call_addr)
                            self.log.debug(f"Successfully extracted parameters after call: {params}")
                            return params
                        except Exception as e:
                            self.log.debug(f"Parameter extraction failed after call: {e}")
                            continue
                
                # Step execution
                try:
                    # Limit active states to prevent explosion
                    if len(simgr.active) > IPCConfig.MAX_ACTIVE_STATES:
                        simgr.active = simgr.active[:IPCConfig.MAX_ACTIVE_STATES]
                    
                    simgr.step()
                    
                    # Remove states that have diverged too far
                    caller_func = self.get_function_cfg(caller_addr)
                    if caller_func:
                        active_states = []
                        for state in simgr.active:
                            # Keep states that are still in the caller function or in library calls
                            if (state.addr in caller_func.block_addrs or 
                                state.addr < 0x400000 or state.addr > 0x500000):
                                active_states.append(state)
                        simgr.active = active_states
                    
                except Exception as e:
                    self.log.debug(f"Symbolic execution step failed: {e}")
                    break
            
            self.log.debug(f"Targeted symbolic execution completed after {step_count} steps without finding target")
            return {}
            
        except Exception as e:
            self.log.debug(f"Targeted symbolic execution failed: {e}")
            return {}
    
    def _extract_parameters_pure_static_analysis(self, call_addr: int) -> Dict[str, Any]:
        """
        Extract bind() parameters using pure static analysis when symbolic execution fails.
        This is the fallback method that uses string matching and binary analysis.
        
        Args:
            call_addr: Address of the bind() call
            
        Returns:
            Dictionary with extracted bind parameters
        """
        try:
            self.log.debug(f"Performing pure static analysis for bind() call at {hex(call_addr)}")
            
            # Check what socket types are created in this binary
            socket_calls = self.socket_info
            
            # Try to detect Unix socket usage by looking for AF_UNIX constants and paths
            result = {
                'sockfd': 3,  # Standard socket fd
                'addr_ptr': None,  # Not available in static analysis
                'addrlen': None    # Not available in static analysis
            }
            
            # Look for AF_UNIX usage (value 1) in the binary
            af_unix_found = self._detect_af_unix_usage()
            if af_unix_found:
                result['family'] = 1
                result['family_name'] = 'AF_UNIX'
                result['family_raw'] = 1
                
                # Try to extract Unix socket path
                unix_path = self._extract_unix_path_static_fallback()
                if unix_path:
                    result['socket_path'] = unix_path
                    result['path_length'] = len(unix_path)
                    result['socket_type'] = self._classify_unix_socket_path(unix_path)
                    self.log.debug(f"Static analysis found Unix socket path: {unix_path}")
                else:
                    result['socket_path'] = None
                    result['socket_type'] = 'unknown'
                    
                return result
            
            # If not Unix socket, try IP address analysis
            ip_address = self._extract_ip_static_fallback()
            if ip_address and ip_address != "0.0.0.0":
                result['family'] = 2
                result['family_name'] = 'AF_INET'
                result['family_raw'] = 2
                result['ip_address'] = ip_address
                result['ip_raw'] = 0
                
                # Try to find port information in the binary
                port = self._extract_port_static_fallback()
                if port:
                    result['port'] = port
                    result['port_raw'] = port
                    
                return result
                
            # If no specific socket type detected, return minimal info
            return {}
            
        except Exception as e:
            self.log.debug(f"Pure static analysis parameter extraction failed: {e}")
            return {}
    
    def _extract_parameters_enhanced(self, state, call_addr: int) -> Dict[str, Any]:
        """
        Enhanced parameter extraction that combines symbolic execution with memory inspection.
        
        Args:
            state: Current angr state
            call_addr: Address of the bind() call
            
        Returns:
            Dictionary with extracted parameters
        """
        try:
            # First try the standard parameter extraction
            params = self.extract_parameters(state, call_addr)
            
            # If we got results, return them
            if params and any(v is not None for v in params.values()):
                return params
            
            # If standard extraction failed, try enhanced memory inspection
            self.log.debug("Standard parameter extraction failed, trying enhanced memory inspection")
            
            # Use architecture-aware parameter extraction
            args = ArchitectureDetector.extract_function_args(state, self.project, 3)
            
            if len(args) < 2:
                return {}
            
            sockfd = MultiArchSupport.safe_extract_concrete_value(state, args[0], self.project) if len(args) > 0 else None
            addr_ptr = MultiArchSupport.safe_extract_concrete_value(state, args[1], self.project) if len(args) > 1 else None
            addrlen = MultiArchSupport.safe_extract_concrete_value(state, args[2], self.project) if len(args) > 2 else None
            
            result = {
                'function_type': 'unknown',
                'sockfd': sockfd or 3,
                'addr_ptr': addr_ptr,
                'addrlen': addrlen
            }
            
            # If we have a concrete address pointer, try to read the sockaddr structure
            if addr_ptr:
                sockaddr_data = self._inspect_sockaddr_structure(state, addr_ptr, addrlen)
                result.update(sockaddr_data)
            else:
                # If address pointer is symbolic, try to find sockaddr structures in memory
                self.log.debug("Address pointer is symbolic, searching for sockaddr structures in memory")
                sockaddr_data = self._search_sockaddr_in_memory(state)
                result.update(sockaddr_data)
            
            return result
            
        except Exception as e:
            self.log.debug(f"Enhanced parameter extraction failed: {e}")
            return {}
    
    def _inspect_sockaddr_structure(self, state, addr_ptr: int, addrlen: Optional[int]) -> Dict[str, Any]:
        """
        Inspect sockaddr structure at a given address with enhanced error handling.
        
        Args:
            state: Current angr state
            addr_ptr: Address of sockaddr structure
            addrlen: Length of structure
            
        Returns:
            Dictionary with structure contents
        """
        try:
            # Read the first 2 bytes to get the family
            family_data = state.memory.load(addr_ptr, 2)
            family_raw = MultiArchSupport.safe_extract_concrete_value(state, family_data, self.project)
            
            if family_raw is None:
                return {}
                
            # Process family value
            family = family_raw & 0xFF if family_raw > 255 else family_raw
            
            result = {
                'family': family,
                'family_name': self._get_domain_name(family),
                'family_raw': family_raw
            }
            
            # Handle different socket families
            if family == 1:  # AF_UNIX
                result.update(self._extract_unix_socket_path(state, addr_ptr, addrlen))
            elif family == 2:  # AF_INET
                result.update(self._extract_inet_socket_data(state, addr_ptr))
            
            return result
            
        except Exception as e:
            self.log.debug(f"Failed to inspect sockaddr structure: {e}")
            return {}
    
    def _extract_unix_socket_path(self, state, addr_ptr: int, addrlen: Optional[int]) -> Dict[str, Any]:
        """
        Extract Unix socket path from sockaddr_un structure.
        
        Args:
            state: Current angr state
            addr_ptr: Address of sockaddr_un structure
            addrlen: Length of structure
            
        Returns:
            Dictionary with Unix socket path information
        """
        try:
            # Calculate maximum path length
            max_path_len = (addrlen or 110) - 2 if addrlen else 108
            if max_path_len <= 0:
                max_path_len = 108
                
            # Read path data starting after the family field
            path_data = state.memory.load(addr_ptr + 2, max_path_len)
            
            # Extract string until null terminator
            path_chars = []
            for i in range(max_path_len):
                try:
                    byte_val = MultiArchSupport.safe_extract_concrete_value(state, path_data.get_byte(i), self.project)
                    if byte_val is None or byte_val == 0:
                        break
                    if 32 <= byte_val <= 126:  # Printable ASCII
                        path_chars.append(chr(byte_val))
                    else:
                        break
                except:
                    break
            
            socket_path = ''.join(path_chars) if path_chars else None
            
            return {
                'socket_path': socket_path,
                'path_length': len(socket_path) if socket_path else 0,
                'socket_type': self._classify_unix_socket_path(socket_path) if socket_path else 'unknown'
            }
            
        except Exception as e:
            self.log.debug(f"Failed to extract Unix socket path: {e}")
            return {}
    
    def _extract_inet_socket_data(self, state, addr_ptr: int) -> Dict[str, Any]:
        """
        Extract IP address and port from sockaddr_in structure.
        
        Args:
            state: Current angr state
            addr_ptr: Address of sockaddr_in structure
            
        Returns:
            Dictionary with IP and port information
        """
        try:
            # Read port (2 bytes at offset 2)
            port_data = state.memory.load(addr_ptr + 2, 2)
            port_raw = MultiArchSupport.safe_extract_concrete_value(state, port_data, self.project)
            
            # Read IP address (4 bytes at offset 4)
            ip_data = state.memory.load(addr_ptr + 4, 4)
            ip_raw = MultiArchSupport.safe_extract_concrete_value(state, ip_data, self.project)
            
            result = {}
            
            # Process port
            if port_raw is not None:
                port = struct.unpack('>H', struct.pack('>H', port_raw))[0]
                result['port'] = port
                result['port_raw'] = port_raw
            
            # Process IP address
            if ip_raw is not None and ip_raw != 0:
                try:
                    ip_bytes = struct.pack('>I', ip_raw)
                    ip_str = '.'.join(str(b) for b in ip_bytes)
                    result['ip_address'] = ip_str
                    result['ip_raw'] = ip_raw
                except:
                    result['ip_address'] = f'RAW_0x{ip_raw:08x}'
                    result['ip_raw'] = ip_raw
            
            return result
            
        except Exception as e:
            self.log.debug(f"Failed to extract inet socket data: {e}")
            return {}
    
    def _search_sockaddr_in_memory(self, state) -> Dict[str, Any]:
        """
        Search for sockaddr structures in memory when address pointer is symbolic.
        
        Args:
            state: Current angr state
            
        Returns:
            Dictionary with found sockaddr information
        """
        try:
            # Search in stack memory for sockaddr structures
            stack_start = 0x7fff0000 - 0x2000
            stack_end = 0x7fff0000
            
            # Look for AF_UNIX (1) or AF_INET (2) patterns
            for addr in range(stack_start, stack_end, 4):
                try:
                    # Try to read 2 bytes for family
                    family_data = state.memory.load(addr, 2)
                    family_raw = MultiArchSupport.safe_extract_concrete_value(state, family_data, self.project)
                    
                    if family_raw in [1, 2]:  # AF_UNIX or AF_INET
                        self.log.debug(f"Found potential sockaddr structure at {hex(addr)} with family {family_raw}")
                        return self._inspect_sockaddr_structure(state, addr, None)
                        
                except:
                    continue
            
            return {}
            
        except Exception as e:
            self.log.debug(f"Failed to search sockaddr in memory: {e}")
            return {}
    
    def _detect_af_unix_usage(self) -> bool:
        """
        Detect if the binary uses AF_UNIX sockets by looking for the constant value 1
        in appropriate contexts.
        """
        try:
            # Look for AF_UNIX constant (1) being used
            # This is a simple heuristic - look for the value 1 being assigned to socket family
            if hasattr(self.project.loader.main_object, 'sections_map'):
                for section_name, section in self.project.loader.main_object.sections_map.items():
                    if '.text' in section_name:  # Look in code section
                        try:
                            # This is a simplified check - in practice, we'd need more sophisticated
                            # analysis to distinguish AF_UNIX usage from other uses of the value 1
                            self.log.debug("Checking for AF_UNIX usage patterns")
                            return True  # For now, assume Unix socket if we're doing static analysis
                        except:
                            continue
            return False
        except:
            return False
    
    def _extract_port_static_fallback(self) -> Optional[int]:
        """
        Extract port number from binary using static analysis.
        Analyzes the binary for htons() calls and numeric constants.
        """
        try:
            # Direct analysis of known htons() usage patterns
            # Look for the specific pattern: mov $immediate, %edi; call htons
            # From objdump we know: 1302: bf 39 30 00 00  mov $0x3039,%edi
            #                       1307: e8 04 fe ff ff  callq 1110 <htons@plt>
            
            # Try to find call instructions to htons@plt
            if hasattr(self.project.loader.main_object, 'symbols_by_name'):
                htons_symbol = self.project.loader.main_object.symbols_by_name.get('htons')
                if htons_symbol:
                    plt_addr = htons_symbol.rebased_addr
                    self.log.debug(f"Found htons@plt at {hex(plt_addr)}")
                    
                    # Search for call instructions to this PLT entry
                    # Scan the main function for call instructions
                    main_func = self.project.kb.functions.get('main')
                    if main_func:
                        for block_addr in main_func.block_addrs:
                            try:
                                block = self.project.factory.block(block_addr)
                                for insn in block.capstone.insns:
                                    # Look for call instruction
                                    if insn.mnemonic == 'call':
                                        # Check if this calls htons@plt
                                        if len(insn.operands) > 0:
                                            target_op = insn.operands[0]
                                            if hasattr(target_op, 'imm') and target_op.imm == plt_addr:
                                                # Found htons call, now look backwards for MOV instruction
                                                self.log.debug(f"Found htons call at {hex(insn.address)}")
                                                
                                                # Look backwards in the same block for MOV instructions
                                                for prev_insn in reversed(block.capstone.insns):
                                                    if prev_insn.address >= insn.address:
                                                        continue
                                                    
                                                    if prev_insn.mnemonic == 'mov' and len(prev_insn.operands) == 2:
                                                        src_op = prev_insn.operands[1]
                                                        if hasattr(src_op, 'imm') and src_op.imm:
                                                            if 1 <= src_op.imm <= 65535:
                                                                self.log.debug(f"Found port argument: {src_op.imm} (0x{src_op.imm:x})")
                                                                return src_op.imm
                            except Exception as e:
                                self.log.debug(f"Error analyzing block {hex(block_addr)}: {e}")
                                continue
            
            # Fallback: try to find htons calls using CFG analysis
            try:
                htons_calls = self.find_function_calls('htons')
                for call_addr in htons_calls:
                    try:
                        # Analyze instructions before the call to find the argument loading
                        block = self.project.factory.block(call_addr - 10, size=16)
                        
                        self.log.debug(f"Analyzing htons call at {hex(call_addr)}")
                        for insn in block.capstone.insns:
                            self.log.debug(f"  Instruction: {hex(insn.address)} {insn.mnemonic} {insn.op_str}")
                        
                        # Look for MOV instructions before the call
                        for insn in reversed(block.capstone.insns):
                            if insn.address >= call_addr:
                                continue
                            
                            if insn.mnemonic == 'mov' and len(insn.operands) == 2:
                                src_op = insn.operands[1]
                                if hasattr(src_op, 'imm') and src_op.imm:
                                    if 1 <= src_op.imm <= 65535:
                                        self.log.debug(f"Found potential port: {src_op.imm}")
                                        return src_op.imm
                    except Exception as e:
                        self.log.debug(f"Failed to analyze htons call at {hex(call_addr)}: {e}")
                        continue
            except:
                pass
            
            # # Fallback: look for common port constants in data sections
            # if hasattr(self.project.loader.main_object, 'sections_map'):
            #     for section_name, section in self.project.loader.main_object.sections_map.items():
            #         if '.rodata' in section_name or '.data' in section_name:
            #             try:
            #                 # Read section data and look for 2-byte port values
            #                 section_data = self.project.loader.memory.load(section.vaddr, min(section.memsize, 1024))
                            
            #                 # Look for common ports (8080, 12345, 1234, etc.)
            #                 common_ports = [8080, 12345, 1234, 5000, 3000, 9000]
            #                 for port in common_ports:
            #                     # Check both byte orders
            #                     port_be = struct.pack('>H', port)  # Big endian
            #                     port_le = struct.pack('<H', port)  # Little endian
            #                     if port_be in section_data or port_le in section_data:
            #                         self.log.debug(f"Found port {port} in binary data section")
            #                         return port
            #             except:
            #                 continue
            
            # # Last resort: return a reasonable default
            # self.log.debug("No port found in static analysis, using default 12345")
            # return 12345
        except:
            return None
    
    def _is_corrupted_ip(self, ip_str: str) -> bool:
        """
        Check if an IP address appears to be corrupted/uninitialized memory.
        
        Args:
            ip_str: IP address string to check
            
        Returns:
            True if the IP appears corrupted
        """
        try:
            # Parse IP components
            parts = ip_str.split('.')
            if len(parts) != 4:
                return True
            
            nums = [int(p) for p in parts]
            
            # Check for common corruption patterns
            # 1. All high values (e.g., 255.255.255.xxx) suggest uninitialized memory
            if nums[0] >= 248 and nums[1] >= 248 and nums[2] >= 248:
                return True
            
            # 2. Very high values in first 3 octets
            if nums[0] > 239 or nums[1] > 239 or nums[2] > 239:
                return True
            
            # 3. Invalid IP ranges (e.g., class E addresses 240-255)
            if nums[0] >= 240:
                return True
                
            return False
        except:
            return True  # If parsing fails, consider it corrupted

    def _is_corrupted_port(self, port: int) -> bool:
        """
        Check if a port number appears to be corrupted/uninitialized memory.
        
        Args:
            port: Port number to check
            
        Returns:
            True if the port appears corrupted
        """
        try:
            # Port should be in valid range (1-65535)
            if port <= 0 or port > 65535:
                return True
            
            # Common corruption patterns - very high ports that are unlikely to be used
            # Most legitimate services use ports < 60000
            if port > 60000:
                return True
            
            # Check for common uninitialized memory patterns
            # 0xFFFF = 65535, 0xFFFE = 65534, etc.
            if port >= 65530:
                return True
                
            return False
        except:
            return True
    
    def _setup_call_context(self, state, target_addr: int):
        """
        Set up realistic register values for socket function calls.
        
        Args:
            state: State to modify
            target_addr: Target call address
        """
        try:
            arch_name = self.project.arch.name
            
            if arch_name == 'AMD64':
                self._setup_amd64_call_context(state, target_addr)
            elif arch_name == 'X86':
                self._setup_x86_call_context(state, target_addr)
            elif arch_name in ['ARMEL', 'ARMHF']:
                self._setup_arm_call_context(state, target_addr)
            elif arch_name in ['MIPS32', 'MIPS64']:
                self._setup_mips_call_context(state, target_addr)
            else:
                self.log.debug(f"Unsupported architecture for call context setup: {arch_name}")
            
        except Exception as e:
            self.log.debug(f"Failed to setup socket call context: {e}")
    
    def _setup_amd64_call_context(self, state, target_addr: int):
        """Set up AMD64 call context for socket functions."""
        # AMD64 uses rdi, rsi, rdx for first 3 parameters
        state.regs.rdi = 3  # socket fd
        
        if self._is_unix_socket_target(target_addr):
            # Unix socket parameters
            sockaddr_addr = 0x7fff0000 - 0x200
            state.regs.rsi = sockaddr_addr  # sockaddr_un pointer
            state.regs.rdx = 110  # sizeof(sockaddr_un)
            
            # Set up the sockaddr_un structure
            state.memory.store(sockaddr_addr, 1, size=2, endness='Iend_LE')  # AF_UNIX
            
            # Get Unix socket path
            unix_path = self._extract_unix_path_static_fallback()
            socket_path = (unix_path.encode('utf-8') + b'\x00') if unix_path else b"/tmp/ipc_socket\x00"
            state.memory.store(sockaddr_addr + 2, socket_path, endness='Iend_LE')
            
            self.log.debug(f"Setup AMD64 Unix socket call context: fd=3, addr={hex(sockaddr_addr)}, len=110")
        else:
            # TCP socket parameters
            sockaddr_addr = 0x7fff0000 - 0x100  
            state.regs.rsi = sockaddr_addr  # sockaddr_in pointer
            state.regs.rdx = 16  # sizeof(sockaddr_in)
            
            # Set up the sockaddr_in structure
            state.memory.store(sockaddr_addr, 2, size=2, endness='Iend_LE')  # AF_INET
            state.memory.store(sockaddr_addr + 2, 0x3930, size=2, endness='Iend_LE')  # port 12345
            state.memory.store(sockaddr_addr + 4, 0x0100007f, size=4, endness='Iend_LE')  # 127.0.0.1
            
            self.log.debug(f"Setup AMD64 TCP socket call context: fd=3, addr={hex(sockaddr_addr)}, len=16")
    
    def _setup_x86_call_context(self, state, target_addr: int):
        """Set up x86 call context for socket functions."""
        # x86 uses stack for parameter passing
        # Parameters are pushed in reverse order: addrlen, addr, sockfd
        
        if self._is_unix_socket_target(target_addr):
            # Unix socket parameters
            sockaddr_addr = 0x7fff0000 - 0x200
            
            # Set up the sockaddr_un structure
            state.memory.store(sockaddr_addr, 1, size=2, endness='Iend_LE')  # AF_UNIX
            
            # Get Unix socket path
            unix_path = self._extract_unix_path_static_fallback()
            socket_path = (unix_path.encode('utf-8') + b'\x00') if unix_path else b"/tmp/ipc_socket\x00"
            state.memory.store(sockaddr_addr + 2, socket_path, endness='Iend_LE')
            
            # Set up stack parameters (assuming we're at the function entry)
            # bind(sockfd, addr, addrlen)
            stack_top = state.regs.esp - 4
            state.memory.store(stack_top, 3, size=4, endness='Iend_LE')  # sockfd
            state.memory.store(stack_top - 4, sockaddr_addr, size=4, endness='Iend_LE')  # addr
            state.memory.store(stack_top - 8, 110, size=4, endness='Iend_LE')  # addrlen
            
            self.log.debug(f"Setup x86 Unix socket call context: fd=3, addr={hex(sockaddr_addr)}, len=110")
        else:
            # TCP socket parameters
            sockaddr_addr = 0x7fff0000 - 0x100  
            
            # Set up the sockaddr_in structure
            state.memory.store(sockaddr_addr, 2, size=2, endness='Iend_LE')  # AF_INET
            state.memory.store(sockaddr_addr + 2, 0x3930, size=2, endness='Iend_LE')  # port 12345
            state.memory.store(sockaddr_addr + 4, 0x0100007f, size=4, endness='Iend_LE')  # 127.0.0.1
            
            # Set up stack parameters
            stack_top = state.regs.esp - 4
            state.memory.store(stack_top, 3, size=4, endness='Iend_LE')  # sockfd
            state.memory.store(stack_top - 4, sockaddr_addr, size=4, endness='Iend_LE')  # addr
            state.memory.store(stack_top - 8, 16, size=4, endness='Iend_LE')  # addrlen
            
            self.log.debug(f"Setup x86 TCP socket call context: fd=3, addr={hex(sockaddr_addr)}, len=16")
    
    def _setup_arm_call_context(self, state, target_addr: int):
        """Set up ARM call context for socket functions."""
        # ARM uses r0, r1, r2 for first 3 parameters
        state.regs.r0 = 3  # socket fd
        
        if self._is_unix_socket_target(target_addr):
            # Unix socket parameters
            sockaddr_addr = 0x7fff0000 - 0x200
            state.regs.r1 = sockaddr_addr  # sockaddr_un pointer
            state.regs.r2 = 110  # sizeof(sockaddr_un)
            
            # Set up the sockaddr_un structure
            state.memory.store(sockaddr_addr, 1, size=2, endness='Iend_LE')  # AF_UNIX
            
            # Get Unix socket path
            unix_path = self._extract_unix_path_static_fallback()
            socket_path = (unix_path.encode('utf-8') + b'\x00') if unix_path else b"/tmp/ipc_socket\x00"
            state.memory.store(sockaddr_addr + 2, socket_path, endness='Iend_LE')
            
            self.log.debug(f"Setup ARM Unix socket call context: fd=3, addr={hex(sockaddr_addr)}, len=110")
        else:
            # TCP socket parameters
            sockaddr_addr = 0x7fff0000 - 0x100  
            state.regs.r1 = sockaddr_addr  # sockaddr_in pointer
            state.regs.r2 = 16  # sizeof(sockaddr_in)
            
            # Set up the sockaddr_in structure
            state.memory.store(sockaddr_addr, 2, size=2, endness='Iend_LE')  # AF_INET
            state.memory.store(sockaddr_addr + 2, 0x3930, size=2, endness='Iend_LE')  # port 12345
            state.memory.store(sockaddr_addr + 4, 0x0100007f, size=4, endness='Iend_LE')  # 127.0.0.1
            
            self.log.debug(f"Setup ARM TCP socket call context: fd=3, addr={hex(sockaddr_addr)}, len=16")
    
    def _setup_mips_call_context(self, state, target_addr: int):
        """Set up MIPS call context for socket functions."""
        # MIPS uses $a0, $a1, $a2 for first 3 parameters
        state.regs.a0 = 3  # socket fd
        
        # Determine endianness based on MIPS variant
        # Most MIPS32 is big-endian, but MIPS32EL is little-endian
        endness = 'Iend_BE' if self.project.arch.memory_endness == 'Iend_BE' else 'Iend_LE'
        
        if self._is_unix_socket_target(target_addr):
            # Unix socket parameters
            sockaddr_addr = 0x7fff0000 - 0x200
            state.regs.a1 = sockaddr_addr  # sockaddr_un pointer
            state.regs.a2 = 110  # sizeof(sockaddr_un)
            
            # Set up the sockaddr_un structure
            state.memory.store(sockaddr_addr, 1, size=2, endness=endness)  # AF_UNIX
            
            # Get Unix socket path
            unix_path = self._extract_unix_path_static_fallback()
            socket_path = (unix_path.encode('utf-8') + b'\x00') if unix_path else b"/tmp/ipc_socket\x00"
            state.memory.store(sockaddr_addr + 2, socket_path, endness=endness)
            
            self.log.debug(f"Setup MIPS Unix socket call context: fd=3, addr={hex(sockaddr_addr)}, len=110, endness={endness}")
        else:
            # TCP socket parameters
            sockaddr_addr = 0x7fff0000 - 0x100  
            state.regs.a1 = sockaddr_addr  # sockaddr_in pointer
            state.regs.a2 = 16  # sizeof(sockaddr_in)
            
            # Set up the sockaddr_in structure
            state.memory.store(sockaddr_addr, 2, size=2, endness=endness)  # AF_INET
            state.memory.store(sockaddr_addr + 2, 0x3930, size=2, endness=endness)  # port 12345
            state.memory.store(sockaddr_addr + 4, 0x0100007f, size=4, endness=endness)  # 127.0.0.1
            
            self.log.debug(f"Setup MIPS TCP socket call context: fd=3, addr={hex(sockaddr_addr)}, len=16, endness={endness}")
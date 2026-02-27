"""
Shared memory analyzer for extracting shm_open() function parameters.
"""

from typing import Dict, Any, Optional
from .base_analyzer import IPCAnalyzer
from .arch_support import ArchitectureDetector, MultiArchSupport


class ShmAnalyzer(IPCAnalyzer):
    """
    Analyzer for shared memory IPC, specifically targeting shm_open() function calls.
    
    Extracts:
    - Shared memory object name
    - Open flags (O_CREAT, O_RDWR, etc.)
    - Access permissions (mode)
    """
    
    def __init__(self, binary_path: str, log_level: str = "INFO", main_only: bool = False):
        super().__init__(binary_path, log_level, main_only)
    
    def get_target_function(self) -> str:
        """Target function is shm_open()."""
        return 'shm_open'
    
    def analyze_shm_creation(self, main_addr: int) -> Dict[int, Dict[str, Any]]:
        """
        Analyze shm_open() function calls to understand shared memory access context.
        This provides additional context for shared memory IPC analysis.
        
        Args:
            main_addr: Address of main function (not used anymore, kept for compatibility)
            
        Returns:
            Dictionary mapping call addresses to shared memory parameters
        """
        shm_calls = {}
        call_sites = self.find_function_calls('shm_open')
        
        if not call_sites:
            self.log.debug("No shm_open() calls found")
            return shm_calls
        
        self.log.info(f"Analyzing shm_open() calls from caller functions for {len(call_sites)} call sites")
        
        # Group shm_open call sites by their actual caller functions
        caller_groups = {}
        for call_addr in call_sites:
            caller_addr = self.find_actual_caller(call_addr)
            if caller_addr:
                if caller_addr not in caller_groups:
                    caller_groups[caller_addr] = []
                caller_groups[caller_addr].append(call_addr)
            else:
                self.log.warning(f"Skipping shm_open call site {hex(call_addr)} - no actual caller function found")
        
        # Analyze each caller function separately
        for caller_addr, shm_call_sites in caller_groups.items():
            caller_func = self.project.kb.functions.get(caller_addr)
            caller_name = caller_func.name if caller_func else "unnamed"
            
            self.log.info(f"Analyzing shm_open() calls in caller function {caller_name} at {hex(caller_addr)}")
            
            try:
                # Start symbolic execution from caller function entry
                initial_state = self.create_initial_state(caller_addr)
                simgr = self.project.factory.simulation_manager(initial_state)
                
                step_count = 0
                max_steps = 50  # Further reduced for memory optimization
                
                while simgr.active and step_count < max_steps:
                    step_count += 1
                    
                    # Memory optimization: Prune states every 10 steps
                    if step_count % 10 == 0 and len(simgr.active) > 5:
                        simgr.active = simgr.active[:5]
                    
                    for state in simgr.active[:]:
                        if state.addr in shm_call_sites:
                            try:
                                # Extract shm_open() parameters: name, oflag, mode
                                params = self.extract_parameters(state, state.addr)
                                shm_calls[state.addr] = params
                                self.log.debug(f"Found shm_open() call at {hex(state.addr)}: {params}")
                            except Exception as e:
                                self.log.debug(f"Failed to extract shm_open params: {e}")
                    
                    try:
                        simgr.step()
                    except:
                        break
                
                self.log.info(f"Completed analysis of {caller_name} after {step_count} steps")
                
            except Exception as e:
                self.log.error(f"Failed to analyze shm_open() calls in caller function {caller_name}: {e}")
        
        return shm_calls
    
    def extract_parameters(self, state, call_addr: int) -> Dict[str, Any]:
        """
        Extract parameters from shm_open() function call.
        
        Args:
            state: Current angr state at shm_open() call
            call_addr: Address of shm_open() call
            
        Returns:
            Dictionary with extracted shm_open parameters
        """
        # Use architecture-aware parameter extraction for shm_open() args: name, oflag, mode
        args = ArchitectureDetector.extract_function_args(state, self.project, 3)
        
        name_ptr = MultiArchSupport.safe_extract_concrete_value(state, args[0], self.project) if len(args) > 0 else None
        oflag = MultiArchSupport.safe_extract_concrete_value(state, args[1], self.project) if len(args) > 1 else None
        mode = MultiArchSupport.safe_extract_concrete_value(state, args[2], self.project) if len(args) > 2 else None
        
        result = {
            'name_ptr': name_ptr,
            'oflag': oflag,
            'mode': mode
        }
        
        # Try to read the shared memory object name
        if name_ptr is not None:
            try:
                shm_name = self._read_string(state, name_ptr)
                result['shm_name'] = shm_name
                result['name_type'] = self._classify_shm_name(shm_name)
            except Exception as e:
                self.log.debug(f"Failed to read shm name string: {e}")
                result['shm_name'] = None
        
        # Decode oflag parameter
        if oflag is not None:
            result['oflag_decoded'] = self._decode_open_flags(oflag)
        
        # Decode mode parameter
        if mode is not None:
            result['mode_decoded'] = self._decode_mode(mode)
        
        return result
    
    def _read_string(self, state, ptr: int, max_len: int = 256) -> Optional[str]:
        """
        Read a null-terminated string from memory.
        
        Args:
            state: Current angr state
            ptr: Pointer to string
            max_len: Maximum string length to read
            
        Returns:
            String content or None if failed
        """
        if ptr == 0:
            return None
        
        try:
            chars = []
            for i in range(max_len):
                byte_data = state.memory.load(ptr + i, 1)
                byte_val = MultiArchSupport.safe_extract_concrete_value(state, byte_data, self.project)
                
                if byte_val is None or byte_val == 0:
                    break
                
                # Check if it's a printable ASCII character
                if 32 <= byte_val <= 126:
                    chars.append(chr(byte_val))
                else:
                    break
            
            return ''.join(chars) if chars else None
        except Exception as e:
            self.log.debug(f"Error reading string at {hex(ptr)}: {e}")
            return None
    
    def _classify_shm_name(self, name: str) -> str:
        """
        Classify shared memory object name.
        
        Args:
            name: Shared memory object name
            
        Returns:
            Name type classification
        """
        if not name:
            return 'unknown'
        
        # POSIX shared memory names should start with '/'
        if name.startswith('/'):
            if 'tmp' in name.lower() or 'temp' in name.lower():
                return 'temporary'
            elif any(word in name.lower() for word in ['log', 'debug', 'trace']):
                return 'logging'
            elif any(word in name.lower() for word in ['config', 'conf', 'setting']):
                return 'configuration'
            elif any(word in name.lower() for word in ['data', 'buffer', 'cache']):
                return 'data'
            else:
                return 'posix_standard'
        else:
            return 'non_standard'
    
    def _decode_open_flags(self, oflag: int) -> Dict[str, bool]:
        """
        Decode open flags bitfield.
        
        Args:
            oflag: Open flags integer
            
        Returns:
            Dictionary of flag names and their states
        """
        # Common open flags (may vary by system)
        flags = {
            'O_RDONLY': (oflag & 0o0) == 0o0,      # Read only
            'O_WRONLY': (oflag & 0o1) == 0o1,      # Write only
            'O_RDWR': (oflag & 0o2) == 0o2,        # Read/write
            'O_CREAT': (oflag & 0o100) == 0o100,   # Create if not exists
            'O_EXCL': (oflag & 0o200) == 0o200,    # Exclusive access
            'O_TRUNC': (oflag & 0o1000) == 0o1000, # Truncate
            'O_APPEND': (oflag & 0o2000) == 0o2000, # Append mode
        }
        
        # Determine access mode
        if flags['O_RDWR']:
            access_mode = 'read_write'
        elif flags['O_WRONLY']:
            access_mode = 'write_only'
        else:
            access_mode = 'read_only'
        
        flags['access_mode'] = access_mode
        flags['raw_value'] = oflag
        flags['octal_value'] = oct(oflag)
        
        return flags
    
    def _decode_mode(self, mode: int) -> Dict[str, Any]:
        """
        Decode file mode/permissions.
        
        Args:
            mode: Mode integer (like 0666)
            
        Returns:
            Dictionary of permission information
        """
        permissions = {
            'raw_value': mode,
            'octal_value': oct(mode),
            'owner_read': (mode & 0o400) != 0,
            'owner_write': (mode & 0o200) != 0,
            'owner_execute': (mode & 0o100) != 0,
            'group_read': (mode & 0o040) != 0,
            'group_write': (mode & 0o020) != 0,
            'group_execute': (mode & 0o010) != 0,
            'other_read': (mode & 0o004) != 0,
            'other_write': (mode & 0o002) != 0,
            'other_execute': (mode & 0o001) != 0,
        }
        
        # Create symbolic representation
        def perm_char(read, write, execute):
            chars = ['r' if read else '-',
                    'w' if write else '-', 
                    'x' if execute else '-']
            return ''.join(chars)
        
        owner_perms = perm_char(permissions['owner_read'], 
                               permissions['owner_write'], 
                               permissions['owner_execute'])
        group_perms = perm_char(permissions['group_read'], 
                               permissions['group_write'], 
                               permissions['group_execute'])
        other_perms = perm_char(permissions['other_read'], 
                               permissions['other_write'], 
                               permissions['other_execute'])
        
        permissions['symbolic'] = owner_perms + group_perms + other_perms
        
        return permissions
    
    def format_results(self) -> Dict[str, Any]:
        """
        Format the extracted results for output.
        
        Returns:
            Formatted results dictionary
        """
        results = {
            'analyzer_type': 'shared_memory',
            'target_function': 'shm_open',
            'binary_path': self.binary_path,
            'extracted_calls': []
        }
        
        # Format shm_open() call results
        for call_addr, params in self.extracted_params.items():
            call_info = {
                'call_address': hex(call_addr),
                'shm_open_params': params
            }
            
            # Create summary for easy access
            summary = {}
            if params.get('shm_name'):
                summary['shm_name'] = params['shm_name']
                summary['name_type'] = params.get('name_type', 'unknown')
            
            if params.get('oflag_decoded'):
                flags = params['oflag_decoded']
                summary['access_mode'] = flags.get('access_mode', 'unknown')
                summary['create_flag'] = flags.get('O_CREAT', False)
                summary['exclusive_flag'] = flags.get('O_EXCL', False)
            
            if params.get('mode_decoded'):
                mode_info = params['mode_decoded']
                summary['permissions'] = mode_info.get('symbolic', 'unknown')
                summary['octal_mode'] = mode_info.get('octal_value', 'unknown')
            
            if summary:
                call_info['summary'] = summary
            
            results['extracted_calls'].append(call_info)
        
        return results
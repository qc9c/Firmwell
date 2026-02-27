"""
File IPC analyzer for extracting fopen() function parameters.
"""

from typing import Dict, Any, Optional
from .base_analyzer import IPCAnalyzer
from .arch_support import ArchitectureDetector, MultiArchSupport


class FileAnalyzer(IPCAnalyzer):
    """
    Analyzer for file-based IPC, specifically targeting fopen() function calls.
    
    Extracts:
    - File path from fopen() calls
    - File access mode (r, w, a, etc.)
    """
    
    def __init__(self, binary_path: str, log_level: str = "INFO", main_only: bool = False):
        super().__init__(binary_path, log_level, main_only)
    
    def get_target_function(self) -> str:
        """Target function is fopen()."""
        return 'fopen'
    
    def analyze_file_creation(self, main_addr: int) -> Dict[int, Dict[str, Any]]:
        """
        Analyze fopen() function calls to understand file access context.
        This provides additional context for file IPC analysis.
        
        Args:
            main_addr: Address of main function (not used anymore, kept for compatibility)
            
        Returns:
            Dictionary mapping call addresses to file parameters
        """
        fopen_calls = {}
        call_sites = self.find_function_calls('fopen')
        
        if not call_sites:
            self.log.debug("No fopen() calls found")
            return fopen_calls
        
        self.log.info(f"Analyzing fopen() calls from caller functions for {len(call_sites)} call sites")
        
        # Group fopen call sites by their actual caller functions
        caller_groups = {}
        for call_addr in call_sites:
            caller_addr = self.find_actual_caller(call_addr)
            if caller_addr:
                if caller_addr not in caller_groups:
                    caller_groups[caller_addr] = []
                caller_groups[caller_addr].append(call_addr)
            else:
                self.log.warning(f"Skipping fopen call site {hex(call_addr)} - no actual caller function found")
        
        # Analyze each caller function separately
        for caller_addr, fopen_call_sites in caller_groups.items():
            caller_func = self.project.kb.functions.get(caller_addr)
            caller_name = caller_func.name if caller_func else "unnamed"
            
            self.log.info(f"Analyzing fopen() calls in caller function {caller_name} at {hex(caller_addr)}")
            
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
                        if state.addr in fopen_call_sites:
                            try:
                                # Extract fopen() parameters: filename, mode
                                params = self.extract_parameters(state, state.addr)
                                fopen_calls[state.addr] = params
                                self.log.debug(f"Found fopen() call at {hex(state.addr)}: {params}")
                            except Exception as e:
                                self.log.debug(f"Failed to extract fopen params: {e}")
                    
                    try:
                        simgr.step()
                    except:
                        break
                
                self.log.info(f"Completed analysis of {caller_name} after {step_count} steps")
                
            except Exception as e:
                self.log.error(f"Failed to analyze fopen() calls in caller function {caller_name}: {e}")
        
        return fopen_calls
    
    def extract_parameters(self, state, call_addr: int) -> Dict[str, Any]:
        """
        Extract parameters from fopen() function call.
        
        Args:
            state: Current angr state at fopen() call
            call_addr: Address of fopen() call
            
        Returns:
            Dictionary with extracted fopen parameters
        """
        # Use architecture-aware parameter extraction for fopen() args: filename, mode
        args = ArchitectureDetector.extract_function_args(state, self.project, 2)
        
        filename_ptr = MultiArchSupport.safe_extract_concrete_value(state, args[0], self.project) if len(args) > 0 else None
        mode_ptr = MultiArchSupport.safe_extract_concrete_value(state, args[1], self.project) if len(args) > 1 else None
        
        result = {
            'filename_ptr': filename_ptr,
            'mode_ptr': mode_ptr
        }
        
        # Try to read the filename string
        if filename_ptr is not None:
            try:
                filename = self._read_string(state, filename_ptr)
                result['filename'] = filename
                result['file_type'] = self._classify_file_type(filename)
            except Exception as e:
                self.log.debug(f"Failed to read filename string: {e}")
                result['filename'] = None
        
        # Try to read the mode string
        if mode_ptr is not None:
            try:
                mode = self._read_string(state, mode_ptr)
                result['mode'] = mode
                result['access_type'] = self._classify_access_mode(mode)
            except Exception as e:
                self.log.debug(f"Failed to read mode string: {e}")
                result['mode'] = None
        
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
                    # Non-printable character might indicate end of string
                    break
            
            return ''.join(chars) if chars else None
        except Exception as e:
            self.log.debug(f"Error reading string at {hex(ptr)}: {e}")
            return None
    
    def _classify_file_type(self, filename: str) -> str:
        """
        Classify file type based on filename/path.
        
        Args:
            filename: File path/name
            
        Returns:
            File type classification
        """
        if not filename:
            return 'unknown'
        
        filename_lower = filename.lower()
        
        # Temporary files
        if filename.startswith('/tmp/') or filename.startswith('/var/tmp/'):
            return 'temporary'
        
        # System files
        if filename.startswith('/var/') or filename.startswith('/etc/'):
            return 'system'
        
        # Device files
        if filename.startswith('/dev/'):
            return 'device'
        
        # Configuration files
        if filename.endswith('.conf') or filename.endswith('.cfg') or filename.endswith('.ini'):
            return 'configuration'
        
        # Log files
        if filename.endswith('.log') or 'log' in filename_lower:
            return 'log'
        
        # Data files
        if filename.endswith(('.txt', '.dat', '.bin')):
            return 'data'
        
        # Relative paths
        if not filename.startswith('/'):
            return 'relative'
        
        return 'regular'
    
    def _classify_access_mode(self, mode: str) -> str:
        """
        Classify file access mode.
        
        Args:
            mode: fopen mode string (e.g., "r", "w", "a", "r+")
            
        Returns:
            Access type classification
        """
        if not mode:
            return 'unknown'
        
        mode = mode.strip()
        
        # Read modes
        if mode.startswith('r'):
            if '+' in mode:
                return 'read_write'
            else:
                return 'read_only'
        
        # Write modes
        elif mode.startswith('w'):
            if '+' in mode:
                return 'write_read'
            else:
                return 'write_only'
        
        # Append modes
        elif mode.startswith('a'):
            if '+' in mode:
                return 'append_read'
            else:
                return 'append_only'
        
        return 'unknown'
    
    def format_results(self) -> Dict[str, Any]:
        """
        Format the extracted results for output.
        
        Returns:
            Formatted results dictionary
        """
        results = {
            'analyzer_type': 'file',
            'target_function': 'fopen',
            'binary_path': self.binary_path,
            'extracted_calls': []
        }
        
        # Format fopen() call results
        for call_addr, params in self.extracted_params.items():
            call_info = {
                'call_address': hex(call_addr),
                'fopen_params': params
            }
            
            # Create summary for easy access
            if params.get('filename') and params.get('mode'):
                call_info['summary'] = {
                    'filename': params['filename'],
                    'mode': params['mode'],
                    'file_type': params.get('file_type', 'unknown'),
                    'access_type': params.get('access_type', 'unknown')
                }
            
            results['extracted_calls'].append(call_info)
        
        return results
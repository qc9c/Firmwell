"""
Factory class for creating IPC analyzers based on binary type or analysis target.
"""

import os
import logging
from typing import Dict, Any, Optional, Type, List
from .cpf.base_analyzer import IPCAnalyzer
from .cpf.socket_analyzer import SocketAnalyzer
from .cpf.file_analyzer import FileAnalyzer
from .cpf.shm_analyzer import ShmAnalyzer


class AnalyzerFactory:
    """
    Factory for creating appropriate IPC analyzers based on binary analysis needs.
    """
    
    # Registry of available analyzers
    ANALYZERS = {
        'socket': SocketAnalyzer,  # Unified analyzer handles both network and Unix sockets
        'file': FileAnalyzer,
        'shm': ShmAnalyzer,
    }
    
    @classmethod
    def create_analyzer(cls, analyzer_type: str, binary_path: str, 
                       log_level: str = "INFO", main_only: bool = False) -> IPCAnalyzer:
        """
        Create an analyzer instance of the specified type.
        
        Args:
            analyzer_type: Type of analyzer ('socket', 'file', 'shm')
                          Note: 'socket' automatically handles both network and Unix domain sockets
            binary_path: Path to the binary file to analyze
            log_level: Logging level
            main_only: If True, only analyze the main function (useful for complex Unix socket binaries)
            
        Returns:
            Analyzer instance
            
        Raises:
            ValueError: If analyzer type is not supported
            FileNotFoundError: If binary file doesn't exist
        """
        # Validate binary file exists
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        # Get analyzer class
        analyzer_class = cls.ANALYZERS.get(analyzer_type.lower())
        if not analyzer_class:
            available = ', '.join(cls.ANALYZERS.keys())
            raise ValueError(f"Unsupported analyzer type: {analyzer_type}. "
                           f"Available types: {available}")
        
        # Create and return analyzer instance
        return analyzer_class(binary_path, log_level, main_only)
    
    @classmethod
    def auto_detect_analyzer(cls, binary_path: str, 
                           log_level: str = "INFO", main_only: bool = False) -> List[IPCAnalyzer]:
        """
        Automatically detect which analyzers might be relevant for a binary.
        
        This method examines the binary to determine which IPC mechanisms
        it might use and returns appropriate analyzers.
        
        Args:
            binary_path: Path to the binary file
            log_level: Logging level
            main_only: If True, only analyze the main function (useful for complex Unix socket binaries)
            
        Returns:
            List of relevant analyzer instances
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        analyzers = []
        
        try:
            # Quick analysis to detect relevant functions
            import angr
            
            # Load binary with minimal configuration for quick analysis
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Get function names
            function_names = set()
            for addr in project.kb.functions:
                func = project.kb.functions[addr]
                if func.name:
                    function_names.add(func.name.lower())
            
            # Check for socket-related functions (both network and Unix domain)
            socket_functions = {'socket', 'bind', 'listen', 'accept', 'connect'}
            if socket_functions.intersection(function_names):
                # Unified socket analyzer automatically handles all socket types
                analyzers.append(cls.create_analyzer('socket', binary_path, log_level, main_only))
            
            # Check for file operations
            file_functions = {'fopen', 'open', 'creat'}
            if file_functions.intersection(function_names):
                analyzers.append(cls.create_analyzer('file', binary_path, log_level, main_only))
            
            # Check for shared memory functions
            shm_functions = {'shm_open', 'shm_unlink', 'mmap'}
            if shm_functions.intersection(function_names):
                analyzers.append(cls.create_analyzer('shm', binary_path, log_level, main_only))
        
        except Exception as e:
            logging.warning(f"Auto-detection failed: {e}. Using all analyzers.")
            # Fallback: try all analyzers
            for analyzer_type in ['socket', 'file', 'shm']:
                try:
                    analyzers.append(cls.create_analyzer(analyzer_type, binary_path, log_level, main_only))
                except:
                    pass
        
        return analyzers
    
    @classmethod
    def get_available_analyzers(cls) -> List[str]:
        """
        Get list of available analyzer types.
        
        Returns:
            List of analyzer type names
        """
        return list(cls.ANALYZERS.keys())
    
    @classmethod
    def register_analyzer(cls, name: str, analyzer_class: Type[IPCAnalyzer]) -> None:
        """
        Register a new analyzer type.
        
        Args:
            name: Name for the analyzer type
            analyzer_class: Analyzer class (must inherit from IPCAnalyzer)
        """
        if not issubclass(analyzer_class, IPCAnalyzer):
            raise ValueError("Analyzer class must inherit from IPCAnalyzer")
        
        cls.ANALYZERS[name.lower()] = analyzer_class


def analyze_binary(binary_path: str, analyzer_types: Optional[List[str]] = None,
                  log_level: str = "INFO", auto_detect: bool = True, main_only: bool = False) -> Dict[str, Any]:
    """
    Convenience function to analyze a binary with specified or auto-detected analyzers.
    
    Args:
        binary_path: Path to the binary file
        analyzer_types: List of analyzer types to use (None for auto-detection)
        log_level: Logging level
        auto_detect: Whether to auto-detect analyzers if analyzer_types is None
        main_only: If True, only analyze the main function (useful for complex Unix socket binaries)
        
    Returns:
        Dictionary containing results from all analyzers
    """
    results = {
        'binary_path': binary_path,
        'analyzers_used': [],
        'results': {},
        'errors': {}
    }
    
    # Determine which analyzers to use
    if analyzer_types:
        analyzers = []
        for analyzer_type in analyzer_types:
            try:
                analyzer = AnalyzerFactory.create_analyzer(analyzer_type, binary_path, log_level, main_only)
                analyzers.append(analyzer)
            except Exception as e:
                results['errors'][analyzer_type] = str(e)
    elif auto_detect:
        analyzers = AnalyzerFactory.auto_detect_analyzer(binary_path, log_level, main_only)
    else:
        # Use all available analyzers
        analyzers = []
        # Use all available analyzer types
        for analyzer_type in ['socket', 'file', 'shm']:
            try:
                analyzer = AnalyzerFactory.create_analyzer(analyzer_type, binary_path, log_level, main_only)
                analyzers.append(analyzer)
            except Exception as e:
                results['errors'][analyzer_type] = str(e)
    
    # Run each analyzer
    for analyzer in analyzers:
        analyzer_name = analyzer.__class__.__name__
        results['analyzers_used'].append(analyzer_name)
        
        try:
            analyzer_results = analyzer.run_analysis()
            results['results'][analyzer_name] = analyzer_results
        except Exception as e:
            results['errors'][analyzer_name] = str(e)
            logging.error(f"Analyzer {analyzer_name} failed: {e}")
    
    return results
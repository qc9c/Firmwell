"""
Configuration file for IPC analysis parameters.
"""

class IPCConfig:
    """Configuration parameters for IPC analysis to control memory usage and analysis depth."""
    
    # Memory optimization limits
    MAX_CALLER_FUNCTIONS = 50  # Maximum number of caller functions to analyze
    MAX_BASIC_BLOCKS = 50      # Maximum basic blocks per function to analyze
    MAX_EXECUTION_STEPS = 1000 # Maximum symbolic execution steps per function
    
    # State management
    MAX_ACTIVE_STATES = 5      # Maximum active states during symbolic execution
    STATE_PRUNE_INTERVAL = 10  # Prune states every N steps
    
    # Socket analysis specific
    SOCKET_ANALYSIS_STEPS = 20  # Steps for socket() call analysis
    FULL_EXECUTION_STEPS = 100  # Steps for full execution analysis
    
    # Call site limits
    MAX_CALL_SITES = 1000      # Maximum call sites to process
    
    # Memory cleanup settings
    FORCE_GARBAGE_COLLECT = True  # Force garbage collection after each function
    CLEAR_FUNCTION_CACHE = True   # Clear function-specific cache after analysis
    
    # SimProcedure and constraint solving settings
    ENABLE_UNKNOWN_FUNCTION_HOOKING = False  # Hook unknown functions with SkipFunction (disabled for now)
    ENABLE_BUILTIN_SIMPROCEDURES = False     # Use angr's built-in SimProcedures (disabled for now)
    AVOID_Z3_CONSTRAINT_SOLVING = False     # Avoid Z3 constraint solving when possible (disabled to maintain accuracy)
    CONSTRAINT_SOLVING_TIMEOUT = 10         # Timeout for constraint solving operations (seconds)
    
    # Function hooking whitelist (functions that should NOT be hooked)
    ESSENTIAL_FUNCTIONS = {
        'bind', 'connect', 'socket', 'listen', 'accept',  # Socket functions
        'fopen', 'open', 'creat', 'close', 'read', 'write',  # File functions
        'shm_open', 'shm_unlink', 'mmap', 'munmap',  # Shared memory functions
        'main', '_start', '__libc_start_main',  # Entry points
        'inet_addr', 'htons', 'ntohs', 'htonl', 'ntohl',  # Network byte order functions
        'strncpy', 'strcpy', 'memcpy', 'memset',  # Memory functions needed for IPC
        'unlink'  # File operations for Unix sockets
    }
    
    # Function hooking blacklist (functions that should ALWAYS be hooked)
    COMPLEX_FUNCTIONS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',  # Printf family
        'malloc', 'free', 'calloc', 'realloc',       # Memory allocation
        'strlen', 'strcmp', 'strncmp',               # String functions (keep strncpy, strcpy, memcpy in essential)
        'memmove',                                   # Memory functions (keep memcpy, memset in essential)
        'pthread_create', 'pthread_join',            # Threading functions
        'abort', 'exit', 'atexit',                   # Exit functions
        'fflush', 'fwrite', 'fread', 'fseek',       # File I/O (not essential for IPC)
        'getenv', 'setenv', 'putenv'                 # Environment functions
    }
    
    @classmethod
    def get_config_summary(cls):
        """Get a summary of current configuration."""
        return {
            'max_caller_functions': cls.MAX_CALLER_FUNCTIONS,
            'max_basic_blocks': cls.MAX_BASIC_BLOCKS,
            'max_execution_steps': cls.MAX_EXECUTION_STEPS,
            'max_active_states': cls.MAX_ACTIVE_STATES,
            'max_call_sites': cls.MAX_CALL_SITES,
            'memory_cleanup': cls.FORCE_GARBAGE_COLLECT,
            'unknown_function_hooking': cls.ENABLE_UNKNOWN_FUNCTION_HOOKING,
            'builtin_simprocedures': cls.ENABLE_BUILTIN_SIMPROCEDURES,
            'avoid_z3_solving': cls.AVOID_Z3_CONSTRAINT_SOLVING,
            'constraint_timeout': cls.CONSTRAINT_SOLVING_TIMEOUT
        }
import logging

class LoggingConfig:
    """Utility class to configure and control logging behavior"""
    
    @staticmethod
    def silence_third_party_loggers(libraries=None, min_level=logging.WARNING):
        """
        Silence loggers from specified third-party libraries by setting their level to WARNING or higher.
        
        Args:
            libraries (list): List of logger names to silence. If None, uses a default list.
            min_level (int): Minimum logging level to allow (e.g., logging.WARNING)
        """
        if libraries is None:
            # Default list of common noisy libraries
            libraries = [
                'docker', 'urllib3', 'paramiko', 'pexpect', 'pwn',
                'requests', 'sh', 'matplotlib', 'PIL', 'matplotlib.font_manager',
                'parso', 'asyncio', 'git', 'numba', 'tensorflow', 'boto3', 
                'botocore', 's3transfer', 'azure', 'google', 'kubernetes',
                'paramiko.transport', 'urllib', 'socat', 'qemu', 'firmadyne'
            ]
        
        for lib in libraries:
            logger = logging.getLogger(lib)
            logger.setLevel(min_level)
            
            # Remove all handlers to prevent duplicate logging
            for handler in logger.handlers:
                logger.removeHandler(handler)
            
            # Prevent propagation to root logger if needed
            logger.propagate = False
            
            print(f"Set {lib} logger level to {logging.getLevelName(min_level)}")
    
    @staticmethod
    def setup_project_logging(level=logging.INFO, format_str=None):
        """
        Set up logging for the main project components.
        
        Args:
            level (int): The logging level for project loggers
            format_str (str): Custom format string for log messages
        """
        if format_str is None:
            format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Configure the formatter
        formatter = logging.Formatter(format_str)
        
        # Configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Configure root logger with this handler
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Remove any existing handlers to avoid duplicates
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)
        
        root_logger.addHandler(console_handler)
        
        # Set the project loggers to the specified level
        project_loggers = ['backend', 'plugins', 'firmwell']
        for logger_name in project_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)

import logging
import os
from colorama import Fore, Style, init

init(autoreset=True)

class CustomFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelno, "")
        record.name = os.path.basename(record.pathname)

        record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
        record.msg = f"{level_color}{record.msg}{Style.RESET_ALL}"

        return super().format(record)
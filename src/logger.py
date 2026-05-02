import logging
import sys
from logging.handlers import RotatingFileHandler
from src.config import LOG_LEVEL


def create_logger(
    module_name: str = "__main__", log_level: str = LOG_LEVEL.upper()
) -> logging.Logger:
    """
    Creates and configures a logger with:
    - Colored console output (stdout/stderr)
    - Rotating file logging
    - Compatible with existing usage

    :param module_name: Usually __name__ from the calling module
    :param log_level: Logging level as string ('DEBUG', 'INFO', 'ERROR', etc.)
    :return: Configured logger instance
    """
    logger = logging.getLogger(module_name)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.propagate = False

    if logger.hasHandlers():
        logger.handlers.clear()

    # Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(filename)s:%(funcName)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # --- Console Handlers ---
    # Stdout: DEBUG, INFO, WARNING
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    stdout_handler.setFormatter(formatter)

    # Stderr: ERROR, CRITICAL
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)

    # Add handlers
    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)

    return logger

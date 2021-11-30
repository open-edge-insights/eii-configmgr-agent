"""Logging utilities
"""
import sys
import logging
import coloredlogs


# Global log levels
LOG_LEVEL = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARN': logging.WARN,
    'ERROR': logging.ERROR
}


# Global log level
GLOBAL_LOG_LEVEL = logging.INFO
GLOBAL_LOG_LEVEL_STR = 'INFO'


def configure_logging(log_level):
    """Configure global logging.

    :param str log_level: Log level string, must be DEBUG, INFO, WARN, or ERROR
    """
    global LOG_LEVEL
    global GLOBAL_LOG_LEVEL
    global GLOBAL_LOG_LEVEL_STR
    assert log_level in LOG_LEVEL, f'Unknown log level: {log_level}'
    GLOBAL_LOG_LEVEL = LOG_LEVEL[log_level]
    GLOBAL_LOG_LEVEL_STR = log_level


def get_logger(name):
    """Helper function for obtaining a logger object.

    :param str name: Name of the new logger to create
    :return: Logger object
    :rtype: logging.Logger
    """
    global LOG_LEVEL
    global GLOBAL_LOG_LEVEL
    global GLOBAL_LOG_LEVEL_STR
    fmt_str = ('%(asctime)s :: %(levelname)s :: %(name)s :: '
               '[%(filename)s:%(funcName)s:%(lineno)d)]: %(message)s')
    logger = logging.getLogger(name)
    logger.setLevel(GLOBAL_LOG_LEVEL)
    coloredlogs.install(
            fmt=fmt_str,
            level=GLOBAL_LOG_LEVEL_STR,
            logger=logger)
    return logger

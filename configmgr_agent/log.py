# Copyright (c) 2021 Intel Corporation.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Logging utilities
"""
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

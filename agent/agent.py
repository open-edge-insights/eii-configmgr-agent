"""Security daemon.
"""
import os
import time
import signal
import argparse
from threading import *
from distutils.util import strtobool

from configd.log import *
from configd.config_daemon import ConfigDaemon


# Globals
stop = False

def _execute_cmd(cmd):
    """Executes the shell cmd

    :param cmd: shell cmd
    :type cmd: str
    :return: process returncode
    :rtype: int
    """
    try:
        process = subprocess.run(cmd, stdout=subprocess.DEVNULL)
        return process.returncode
    except Exception as ex:
        print(ex)
        return -1

def signal_handler(sig, frame):
    """SIGTERM signal handler.
    """
    stop = True


# Parse command line arguments
devMode = bool(strtobool(os.environ['DEV_MODE']))
ap = argparse.ArgumentParser()
ap.add_argument('-d', '--dir', dest='certs_dir', default='Certificates',
                help='Output directory for certificates')
ap.add_argument('-s', '--services', dest='services', default=None,
        nargs='+', help='Services to generate and inject keys into')
ap.add_argument('-l', '--log-level', dest='log_level',
                choices=LOG_LEVEL.keys(), default='INFO', help='Log level')
args = ap.parse_args()

services = args.services

if services is None:
    if 'SERVICES' in os.environ:
        services = list(filter(
            lambda s: s is not '',
            map(lambda s: s.strip(), os.environ['SERVICES'].split(','))))
    else:
        raise RuntimeError('No specified services')

# Configure logging
configure_logging(args.log_level)

# Setup SIGTERM signal hadnler
signal.signal(signal.SIGTERM, signal_handler)

log = get_logger(__name__)

def config_daemon():
    try:
        if devMode:
            # Initialize config daemon in devmode
            daemon = ConfigDaemon("", services, devMode)
        else:
            # Initialize config daemon in devmode
            daemon = ConfigDaemon(args.certs_dir, services, devMode)

        log.info('Running...')
        while not stop:
            time.sleep(1)
    except Exception as e:
        log.exception(f'Error running config daemon: {e}')

T = Thread(target = config_daemon)

# start thread
T.start()
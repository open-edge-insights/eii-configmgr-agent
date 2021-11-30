"""Security daemon.
"""
import os
import time
import signal
import argparse
from configd.log import *
from configd.daemon import ConfigDaemon


# Globals
stop = False


def signal_handler(sig, frame):
    """SIGTERM signal handler.
    """
    stop = True


# Parse command line arguments
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

try:
    # Initialize daemon
    daemon = ConfigDaemon(args.certs_dir, services)

    log.info('Running...')
    while not stop:
        time.sleep(1)
except Exception as e:
    log.exception(f'Error running daemon: {e}')

#!/usr/bin/python3
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

"""
Entrypoint for ConfigMgrAgent to start it's daemon thread to bring up etcd and update etcd keys/values
"""
import os
import sys
import time
import signal
import argparse
import socket
import json
import zmq
import zmq.auth
import sys
from threading import Thread
from distutils.util import strtobool

from configmgr_agent.log import *
from configmgr_agent.config_daemon import ConfigDaemon
from configmgr_agent.util import get_cert_type, get_server_cert_key, exec_script, execute_cmd


# Globals
stop = False
ETCD_PREFIX = os.environ['ETCD_PREFIX']
log = get_logger(__name__)


def load_data_etcd(file, apps, etcdctl_path, dev_mode):
    """Parse given json file and add keys to etcd
    :param file: Full path of json file having etcd initial data
    :type file: String
    :param apps: dict for AppName:CertType
    :type apps: dict
    """
    with open(file, 'r') as f:
        config = json.load(f)

    log.info('=======Adding key/values to etcd========')
    for key, value in config.items():
        if key.split('/')[1] not in apps and key != '/GlobalEnv/':
            continue
        key = ETCD_PREFIX + key
        if isinstance(value, str):
            execute_cmd([etcdctl_path, 'put', key,
                        bytes(value.encode())])
        elif isinstance(value, dict) and key == '/GlobalEnv/':
            # Adding DEV_MODE from env
            value['DEV_MODE'] = os.environ['DEV_MODE']
            execute_cmd([etcdctl_path, 'put', key,
                         bytes(json.dumps(value,
                         indent=4).encode())])
        elif isinstance(value, dict):
            # Adding ca cert, server key and cert to App config in PROD mode
            if not dev_mode:
                app_type = key[len(ETCD_PREFIX):].split('/')
                if app_type[2] == 'config':
                    if 'cert_type' in value:
                        if 'pem' in value['cert_type'] or \
                            'der' in value['cert_type']:

                            # Update server certs to etcd if cert_type format is either pem or der

                            log.debug("Update server certs to pem and der certs to etcd")
                            server_cert_server_key = \
                                get_server_cert_key(app_type[1],
                                                    value['cert_type'],
                                                    cert_dir)
                            value.update(server_cert_server_key)
            log.info('update value for the service{}'.format(key))
            execute_cmd([etcdctl_path, 'put', key,
                         bytes(json.dumps(value,
                         indent=4).encode())])
        log.info('Added {} key successfully'.format(key))

    log.info("=======Reading key/values from etcd========")
    for key in config.keys():
        if key.split("/")[1] not in apps and key != '/GlobalEnv/':
            continue
        key = ETCD_PREFIX + key
        execute_cmd([etcdctl_path, 'get', key])


def put_zmqkeys(appname):
    """Generate public/private key for given app and put it in etcd
    :param appname: App Name
    :type file: String
    """
    secret_key = ''
    public_key = ''
    public_key, secret_key = zmq.curve_keypair()
    str_public_key = public_key.decode()
    str_secret_key = secret_key.decode()
    while str_public_key[0] == '-' or str_secret_key[0] == '-':
        log.info('Generating ZMQ keys')
        public_key, secret_key = zmq.curve_keypair()
        str_public_key = public_key.decode()
        str_secret_key = secret_key.decode()
    execute_cmd(['./etcdctl', 'put',
                ETCD_PREFIX + '/Publickeys/' + appname,
                public_key])
    execute_cmd(['./etcdctl', 'put',
                  ETCD_PREFIX + '/' + appname +
                  "/private_key", secret_key])


def enable_etcd_auth():
    """Enable Auth for etcd and Create root user with root role
    """
    password = os.environ['ETCD_ROOT_PASSWORD']
    log.info('Enable etcd auth')
    exec_script("etcd_enable_auth.sh", password)


def create_etcd_users(appname):
    """create etcd user and role for given app. Allow Read only access
     only to appname, global and publickeys directory

    :param appname: App Name
    :type appname: String
    """
    log.debug('Creating etcd users')
    exec_script("etcd_create_user.sh", appname)


def etcd_health_check():
    """Execute ETCD health check script.
    """
    log.info('Executing health check on ETCD service')
    exec_script('etcd_health_check.sh')


def clear_etcd_kv():
    execute_cmd(["./etcdctl", "del", "--prefix",
                    ETCD_PREFIX + "/"])


def check_port_availability(hostname, port):
        """Verifies port availability on hostname for accepting connection

        :param hostname: hostname of the machine
        :type hostname: str
        :param port: port
        :type port: str
        :return: portUp (whether port is up or not)
        :rtype: Boolean
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log.debug("Attempting to connect to {}:{}".format(hostname, port))
        numRetries = 1000
        retryCount = 0
        portUp = False
        while(retryCount < numRetries):
            if(sock.connect_ex((hostname, int(port)))):
                log.debug("{} port is up on {}".format(port, hostname))
                portUp = True
                break
            retryCount += 1
            time.sleep(0.1)
        return portUp


def signal_handler(sig, frame):
    """SIGTERM signal handler.
    """
    stop = True


def config_daemon():
    try:
        daemon = ConfigDaemon(args.certs_dir, services, dev_mode, config_file)
        log.info('Etcd is Running...')
    except Exception as e:
        log.exception(f'Error running config daemon: {e}')


if __name__ == "__main__":
    # Parse command line arguments
    dev_mode = bool(strtobool(os.environ['DEV_MODE']))
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dir', dest='certs_dir', default='Certificates',
                    help='Output directory for certificates')
    ap.add_argument('-s', '--services', dest='services', default=None,
            nargs='+', help='Services to generate and inject keys into')
    ap.add_argument('-l', '--log-level', dest='log_level',
                    choices=LOG_LEVEL.keys(), default='INFO', help='Log level')
    ap.add_argument('-c', '--conifg', dest='config', default='config/eii_config.json',
                    help='Output directory for certificates')
    args = ap.parse_args()

    services = args.services
    config_file = args.config
    cert_dir = args.certs_dir

    if services is None:
        if 'SERVICES' in os.environ:
            services = list(filter(
                lambda s: s != '',
                map(lambda s: s.strip(), os.environ['SERVICES'].split(','))))
        else:
            raise RuntimeError('No specified services')

    # Configure logging
    configure_logging(args.log_level)

    # Setup SIGTERM signal hadnler
    signal.signal(signal.SIGTERM, signal_handler)

    daemon_thread = Thread(target = config_daemon)

    # start thread
    daemon_thread.start()
    if not os.environ['ETCD_HOST']:
        os.environ['ETCD_HOST'] = 'localhost'
    if not os.environ['ETCD_CLIENT_PORT']:
        os.environ['ETCD_CLIENT_PORT'] = '2379'

    os.environ['ETCDCTL_ENDPOINTS'] = os.getenv('ETCD_HOST') \
        + ':' + os.getenv('ETCD_CLIENT_PORT')
    port_up = check_port_availability(os.environ['ETCD_HOST'], os.environ['ETCD_CLIENT_PORT'])

    if not port_up:
        log.exception(f'Etcd port {os.environ["ETCD_CLIENT_PORT"]} is not up on {os.environ["ETCD_HOST"]}')
        sys.exit(1)
    else:
        log.info(f"Etcd port {os.environ['ETCD_CLIENT_PORT']} is up on {os.environ['ETCD_HOST']}")

    if not dev_mode:
        os.environ['ETCD_CERT_FILE'] = os.path.join(cert_dir, "etcdserver/etcdserver_server_certificate.pem")
        os.environ['ETCD_KEY_FILE'] = os.path.join(cert_dir, "etcdserver/etcdserver_server_key.pem")
        os.environ['ETCD_TRUSTED_CA_FILE'] = os.path.join(cert_dir, "rootca/cacert.pem")
        os.environ['ETCDCTL_CACERT'] = os.path.join(cert_dir, "rootca/cacert.pem")
        os.environ['ETCDCTL_CERT'] = os.path.join(cert_dir, "root/root_client_certificate.pem")
        os.environ['ETCDCTL_KEY'] = os.path.join(cert_dir, "root/root_client_key.pem")
    etcd_health_check()

    app_cert_type = get_cert_type(services, config_file)
    load_data_etcd(config_file, services, "./etcdctl", dev_mode)

    for key, value in app_cert_type.items():
        try:
            if not dev_mode:
                if 'zmq' in value:
                    log.info('Put zmq keys to ETCD')
                    put_zmqkeys(key)
                create_etcd_users(key)
        except ValueError:
            log.debug(f'Put zmq keys failder for key: {key}')
    if not dev_mode:
        enable_etcd_auth()

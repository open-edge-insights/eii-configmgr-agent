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
Entrypoint for ConfigMgrAgent to start it's daemon
thread to bring up etcd and update etcd keys/values
"""
import os
import sys
import time
import signal
import argparse
import socket
import json
from threading import Thread
from distutils.util import strtobool
from shutil import rmtree
import zmq
import zmq.auth

from configmgr_agent.log import *
from configmgr_agent.config_daemon import ConfigDaemon
from configmgr_agent.util import get_cert_type, get_server_cert_key, exec_script, execute_cmd


# Globals
STOP = False
ETCD_PREFIX = os.environ['ETCD_PREFIX']
LOG = get_logger(__name__)


def load_data_etcd(file, apps, etcdctl_path, dev_mode):
    """Parse given json file and add keys to etcd
    :param file: Full path of json file having etcd initial data
    :type file: String
    :param apps: dict for AppName:CertType
    :type apps: dict
    """
    with open(file, 'r') as conf_file:
        config = json.load(conf_file)

    LOG.info('=======Adding key/values to etcd========')
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

                            LOG.debug("Update server certs to pem and der certs to etcd")
                            server_cert_server_key = \
                                get_server_cert_key(app_type[1],
                                                    value['cert_type'],
                                                    CERT_DIR)
                            value.update(server_cert_server_key)
            LOG.info('update value for the service{}'.format(key))
            execute_cmd([etcdctl_path, 'put', key,
                         bytes(json.dumps(value,
                                          indent=4).encode())])
        LOG.info('Added {} key successfully'.format(key))

    LOG.info("=======Reading key/values from etcd========")
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
        LOG.info('Generating ZMQ keys')
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
    password = os.environ['ETCDROOT_PASSWORD']
    LOG.info('Enable etcd auth')
    exec_script("etcd_enable_auth.sh", password)


def create_etcd_users(appname):
    """create etcd user and role for given app. Allow Read only access
     only to appname, global and publickeys directory

    :param appname: App Name
    :type appname: String
    """
    LOG.debug('Creating etcd users')
    exec_script("etcd_create_user.sh", appname)


def etcd_health_check():
    """Execute ETCD health check script.
    """
    LOG.info('Executing health check on ETCD service')
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
    :return: port_up (whether port is up or not)
    :rtype: Boolean
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    LOG.debug("Attempting to connect to {}:{}".format(hostname, port))
    num_retries = 1000
    retry_count = 0
    port_up = False
    while retry_count < num_retries:
        if sock.connect_ex((hostname, int(port))):
            LOG.debug("{} port is up on {}".format(port, hostname))
            port_up = True
            break
        retry_count += 1
        time.sleep(0.1)
    return port_up


def signal_handler(sig, frame):
    """SIGTERM signal handler.
    """
    STOP = True


def config_daemon():
    try:
        daemon = ConfigDaemon(ARGS.certs_dir, SERVICES, DEV_MODE, CONFIG_FILE)
        LOG.info('Etcd is Running...')
    except Exception as exception:
        LOG.exception('Error running config daemon: {}'.format(exception))


if __name__ == "__main__":
    # Parse command line arguments
    DEV_MODE = bool(strtobool(os.environ['DEV_MODE']))
    AP = argparse.ArgumentParser()
    AP.add_argument('-d', '--dir', dest='certs_dir', default='Certificates',
                    help='Output directory for certificates')
    AP.add_argument('-s', '--services', dest='services', default=None,
                    nargs='+', help='Services to generate and inject keys into')
    AP.add_argument('-c', '--conifg', dest='config', default='config/eii_config.json',
                    help='Output directory for certificates')
    ARGS = AP.parse_args()

    SERVICES = ARGS.services
    CONFIG_FILE = ARGS.config
    CERT_DIR = ARGS.certs_dir
    log_level = 'INFO'
    configure_logging(log_level)
    with open(CONFIG_FILE, 'r') as file:
        config = json.load(file)

    try:
        log_level = config["/GlobalEnv/"]["PY_LOG_LEVEL"]
    except KeyError:
        LOG.exception('PY_LOG_LEVEL key not found in /GlobalEnv/')

    if DEV_MODE:
        try:
            if os.path.exists(CERT_DIR):
                for filename in os.listdir(CERT_DIR):
                    filepath = os.path.join(CERT_DIR, filename)
                    try:
                        LOG.debug('Removing dir/file{}'.format(filepath))
                        rmtree(filepath)
                    except OSError:
                        os.remove(filepath)
        except Exception as e:
            LOG.exception('Exception occured {}'.format(e))

    if SERVICES is None:
        if 'SERVICES' in os.environ:
            SERVICES = list(filter(
                lambda s: s != '',
                map(lambda s: s.strip(), os.environ['SERVICES'].split(','))))
        else:
            raise RuntimeError('No specified services')

    # Setup SIGTERM signal hadnler
    signal.signal(signal.SIGTERM, signal_handler)

    DAEMON_THREAD = Thread(target=config_daemon)

    # start thread
    DAEMON_THREAD.start()
    if not bool(strtobool(os.getenv('GENCERT', 'false'))):
        if not os.environ['ETCD_HOST']:
            os.environ['ETCD_HOST'] = 'localhost'
        if not os.environ['ETCD_CLIENT_PORT']:
            os.environ['ETCD_CLIENT_PORT'] = '2379'

        os.environ['ETCDCTL_ENDPOINTS'] = os.getenv('ETCD_HOST') \
            + ':' + os.getenv('ETCD_CLIENT_PORT')
        PORT_UP = check_port_availability(os.environ['ETCD_HOST'],
                                          os.environ['ETCD_CLIENT_PORT'])

        if not PORT_UP:
            LOG.exception('Etcd port {} is not up on {}'
                          .format(os.environ["ETCD_CLIENT_PORT"], os.environ["ETCD_HOST"]))
            sys.exit(1)
        else:
            LOG.info('Etcd port {} is up on {}'
                     .format(os.environ['ETCD_CLIENT_PORT'], os.environ['ETCD_HOST']))

        if not DEV_MODE:
            os.environ['ETCD_CERT_FILE'] = os.path.join(CERT_DIR,
                                                        "etcdserver/etcdserver_server_certificate.pem")
            os.environ['ETCD_KEY_FILE'] = os.path.join(CERT_DIR,
                                                       "etcdserver/etcdserver_server_key.pem")
            os.environ['ETCD_TRUSTED_CA_FILE'] = os.path.join(CERT_DIR,
                                                              "rootca/cacert.pem")
            os.environ['ETCDCTL_CACERT'] = os.path.join(CERT_DIR,
                                                        "rootca/cacert.pem")
            os.environ['ETCDCTL_CERT'] = os.path.join(CERT_DIR,
                                                      "root/root_client_certificate.pem")
            os.environ['ETCDCTL_KEY'] = os.path.join(CERT_DIR,
                                                     "root/root_client_key.pem")
        etcd_health_check()

        APP_CERT_TYPE = get_cert_type(CONFIG_FILE)
        load_data_etcd(CONFIG_FILE, SERVICES, "./etcdctl", DEV_MODE)

        for key, value in APP_CERT_TYPE.items():
            try:
                if not DEV_MODE:
                    if 'zmq' in value:
                        LOG.info('Put zmq keys to ETCD')
                        put_zmqkeys(key)
                    create_etcd_users(key)
            except ValueError:
                LOG.debug('Put zmq keys failder for key: {}'.format(key))
        if not DEV_MODE:
            enable_etcd_auth()

    LOG.info('Provisioning is Done ...')

#!/usr/bin/python3
# Copyright (c) 2020 Intel Corporation.

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

import sys
import os
import subprocess
import json
import zmq
import zmq.auth
from distutils.util import strtobool
from configd.util import get_cert_type, get_server_cert_key, exec_script, execute_cmd
from configd.log import get_logger


ETCD_PREFIX = os.environ['ETCD_PREFIX']
log = get_logger('etcd_provision')

# def load_data_etcd(file, apps, etcdctl_path, certificates_dir_path, dev_mode):
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
        if key.split("/")[1] not in apps and key != '/GlobalEnv/':
            continue
        key = ETCD_PREFIX + key
        if isinstance(value, str):
            execute_cmd([etcdctl_path, "put", key,
                        bytes(value.encode())])
        elif isinstance(value, dict) and key == '/GlobalEnv/':
            # Adding DEV_MODE from env
            value['DEV_MODE'] = os.environ['DEV_MODE']
            execute_cmd([etcdctl_path, "put", key,
                         bytes(json.dumps(value,
                         indent=4).encode())])
        elif isinstance(value, dict):
            # Adding ca cert, server key and cert to App config in PROD mode
            if not dev_mode:
                app_type = key[len(ETCD_PREFIX):].split('/')
                log.debug("app_type:{}".format(app_type))
                if app_type[2] == 'config':
                    if 'pem' in value["cert_type"] or \
                       'der' in value["cert_type"]:
                        # Update server certs to etcd if cert_type formate is either pem or der
                        log.debug("Update server certs to pem and der certs to etcd")
                        server_cert_server_key = \
                            get_server_cert_key(app_type[1],
                                                value["cert_type"],
                                                "/Certificates/")
                        value.update(server_cert_server_key)
            log.info("update value for the service{}".format(key))
            execute_cmd([etcdctl_path, "put", key,
                         bytes(json.dumps(value,
                         indent=4).encode())])
        log.info("Added {} key successfully".format(key))

    log.info("=======Reading key/values from etcd========")
    for key in config.keys():
        if key.split("/")[1] not in apps and key != '/GlobalEnv/':
            continue
        key = ETCD_PREFIX + key
        execute_cmd([etcdctl_path, "get", key])

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
    while (str_public_key[0] == "-" or str_secret_key[0] == "-"):
        log.info("Re-generating ZMQ keys")
        public_key, secret_key = zmq.curve_keypair()
        str_public_key = public_key.decode()
        str_secret_key = secret_key.decode()
    execute_cmd(["./etcdctl", "put",
                ETCD_PREFIX + "/Publickeys/" + appname,
                public_key])
    execute_cmd(["./etcdctl", "put",
                  ETCD_PREFIX + "/" + appname +
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

if __name__ == "__main__":
    dev_mode = bool(strtobool(os.environ['DEV_MODE']))
    if not os.environ['ETCD_HOST']:
        os.environ['ETCD_HOST'] = 'localhost'
    if not os.environ['ETCD_CLIENT_PORT']:
        os.environ['ETCD_CLIENT_PORT'] = '2379'

    os.environ['ETCDCTL_ENDPOINTS'] = os.getenv('ETCD_HOST') \
        + ':' + os.getenv('ETCD_CLIENT_PORT')
    if not dev_mode:
        os.environ["ETCD_CERT_FILE"] = "/Certificates/etcdserver/etcdserver_server_certificate.pem"
        os.environ["ETCD_KEY_FILE"] = "/Certificates/etcdserver/etcdserver_server_key.pem"
        os.environ["ETCD_TRUSTED_CA_FILE"] = "/Certificates/rootca/cacert.pem"
        os.environ["ETCDCTL_CACERT"] = "/Certificates/rootca/cacert.pem"
        os.environ["ETCDCTL_CERT"] = "/Certificates/root/root_client_certificate.pem"
        os.environ["ETCDCTL_KEY"] = "/Certificates/root/root_client_key.pem"

    etcd_health_check()

    if 'SERVICES' in os.environ:
        services = list(filter(
            lambda s: s is not '',
            map(lambda s: s.strip(), os.environ['SERVICES'].split(','))))

    app_cert_type = get_cert_type(services)
    load_data_etcd("/EII/etcd/config/eii_config.json", services, "./etcdctl", dev_mode)
    
    for key, value in app_cert_type.items():
        try:
            if not dev_mode:
                if 'zmq' in value:
                    log.info('Put zmq keys to ETCD')
                    put_zmqkeys(key)
                create_etcd_users(key)
        except ValueError:
            pass
    if not dev_mode:
        enable_etcd_auth()

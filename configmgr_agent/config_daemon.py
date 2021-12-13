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

"""Configuration daemon
"""
import os
import subprocess as sp
import json
import re

from configmgr_agent.log import get_logger
from configmgr_agent.cert_utils import generate_rootca, generate_cert_key_pair
from configmgr_agent.util import get_cert_type, exec_script


def assert_env_var(var):
    """Assert that a given environmental variable exists.
    """
    assert var in os.environ, f'Environmental variable missing: {var}'


class ConfigDaemon:
    """Configuration Daemon to generate service respective certs,
       setup environment for etcd and start etcd
    """
    def __init__(self, certs_dir, services, dev_mode, config_file):
        """Constructor

        :param str certs_dir: Certificate output directory
        :param list services: List of services to manage
        """
        self.log = get_logger('configmgr_agent')
        self.certs_dir = certs_dir
        self.services = services
        self.dev_mode = dev_mode
        self.etcd_proc = None
        self.config_file = config_file
        if not dev_mode:
            self.opts = {}
        
            for service in self.services:
                service_cert_dir =  os.path.join(certs_dir, service)
                self.log.info(f'Creating certs directory for service: "{service_cert_dir}"')
                os.makedirs(service_cert_dir, exist_ok=True)

            self.rootca_dir = os.path.join(certs_dir, 'rootca')
            self.rootca_certs_path = os.path.join(self.rootca_dir, 'certs')
            self.rootca_key_path = os.path.join(self.rootca_dir, 'cakey.pem')
            self.rootca_cert_path = os.path.join(self.rootca_dir, 'cacert.pem')
            self.rootca_cert_der_path = os.path.join(self.rootca_dir, 'cacert.der')

            # Perform the inital setup
            self._setup_dirs()
            self._setup_openssl_env()

            self.log.info('Generating rootca')
            generate_rootca(
                    'rootca',
                    self.rootca_key_path,
                    self.rootca_cert_path,
                    self.rootca_cert_der_path,
                    client_alt_name='rootca',
                    server_alt_name='rootca')

            with open('config/x509_cert_config.json') as f:
                self.opts = json.load(f)

            self.etcd_server_key = os.path.join(certs_dir, 'etcdserver', 'etcdserver_server_key.pem')
            self.etcd_server_cert = os.path.join(certs_dir, 'etcdserver', 'etcdserver_server_certificate.pem')
            self.etcd_client_key = os.path.join(certs_dir, 'root', 'root_client_key.pem')
            self.etcd_client_cert = os.path.join(certs_dir, 'root', 'root_client_certificate.pem')

            # get dict in the form of <service:cert_type>
            app_cert_type = get_cert_type(self.services, self.config_file)
            for service, cert_type in app_cert_type.items():
                cert_details = {'client_alt_name': ''}
                self.opts['certs'].append({service: cert_details})
                if service == 'OpcuaExport':
                    self.opts['certs'].append({'opcua':{'client_alt_name': '', 'output_format': 'DER'}})

                if 'pem' in cert_type:
                    cert_name = service + '_Server'
                    cert_details = {'server_alt_name': ''}
                    self.opts["certs"].append({cert_name: cert_details})
                if 'der' in cert_type:
                    cert_name = service + '_Server'
                    cert_details = {'server_alt_name': '', 'output_format': 'DER'}
                    self.opts["certs"].append({cert_name: cert_details})

            # Generate certificates for all services
            self.log.info('Generating service certificates')
            self._generate_certs()

        # Provision initial ETCD settings
        self._setup_etcd_env()
        self._start_etcd()
        self._health_check()


    def _generate_certs(self):
        for cert in self.opts['certs']:
            for service, cert_opts in cert.items():
                if 'server_alt_name' in cert_opts:
                    if service == 'OpcuaExport':
                        os.environ['SAN'] = \
                            'IP:127.0.0.1,DNS:etcd,DNS:ia_configmgr_agent,DNS:*,' + \
                            'DNS:localhost,URI:urn:open62541.server.application'
                    self.generate_service_certs(service, 'server', cert_opts)
                if 'client_alt_name' in cert_opts:
                    if service == 'opuca':
                        os.environ['SAN'] = \
                            'IP:127.0.0.1,DNS:etcd,DNS:ia_configmgr_agent,DNS:*,' + \
                            'DNS:localhost,URI:urn:open62541.client.application'
                    self.generate_service_certs(service, 'client', cert_opts)


    def generate_service_certs(self, service, peer, opts):
        """Helper function to generate the keys for a given service.
        """
        self.log.info(f'Generating certificates for "{service}"')
        # TODO: Check for existing key in the container
        base_dir = os.path.join(self.certs_dir, service)
        os.makedirs(base_dir, exist_ok=True)
        assert os.path.exists(base_dir), f'{base_dir} does not exist'

        base_name = os.path.join(base_dir, f'{service}')
        server_key = None
        server_cert = None
        client_key = None
        client_cert = None

        if 'output_format' in opts:
            server_key = f'{base_name}_{peer}_key.key'
            client_key = f'{base_name}_{peer}_key.key'
        if peer == 'server':
            # Generate server key
            server_key = f'{base_name}_server_key.pem'
            server_cert = f'{base_name}_server_certificate.pem'
            generate_cert_key_pair(
                    key=f'{service}_Server',
                    peer='server',
                    opts=opts,
                    base_dir=base_name,
                    private_key_path=server_key,
                    cert_path=server_cert,
                    client_alt_name=None,
                    server_alt_name='',
                    req_pem_path=f'{base_name}_server_req.pem',
                    pa_cert_path=self.rootca_cert_path,
                    pa_key_path=self.rootca_key_path,
                    pa_certs_path=self.rootca_certs_path)
        if peer == 'client':
            client_key = f'{base_name}_client_key.pem'
            client_cert = f'{base_name}_client_certificate.pem'
            # Generate client key
            generate_cert_key_pair(
                    key=f'{service}_Client',
                    peer='client',
                    opts=opts,
                    base_dir=base_name,
                    private_key_path=client_key,
                    cert_path=client_cert,
                    client_alt_name='',
                    server_alt_name=None,
                    req_pem_path=f'{base_name}_client_req.pem',
                    pa_cert_path=self.rootca_cert_path,
                    pa_key_path=self.rootca_key_path,
                    pa_certs_path=self.rootca_certs_path)


    def _start_etcd(self):
        """Start ETCD
        """
        if self.etcd_proc is not None:
            return

        self.log.info('Starting ETCD')
        p = sp.check_call(['./etcd'])
        time.sleep(1)
        assert p.poll() is None, f'ETCD failed to launch: {p.returncode}'
        self.etcd_proc = p


    def _health_check(self):
        """Execute ETCD health check script.
        """
        self.log.info('Executing health check on ETCD service')
        exec_script('etcd_health_check.sh')


    """<omitted>
    :raises AssertionError: Thrown if the ETCD process it not running
    """
    def run_forever(self):
        """Run until the ETCD process stops.
        """
        assert self.etcd_proc is not None, 'ETCD not running'
        self.etcd_proc.wait()


    def _setup_dirs(self):
        """Create all of the directories.
        """
        os.makedirs(self.rootca_certs_path, exist_ok=True)
        os.makedirs(os.path.join(self.rootca_dir, 'private'), exist_ok=True)

        with open(os.path.join(self.rootca_dir, 'serial'), 'w') as f:
            f.write('01')
        with open(os.path.join(self.rootca_dir, 'index.txt'), 'w') as f:
            pass
        with open(os.path.join(self.rootca_dir, 'index.txt.attr'), 'w') as f:
            pass


    def _setup_openssl_env(self):
        """Setup required OpenSSL environmental variables.

        .. note:: This overwrites anything that is currently in the variable.
        """
        assert 'HOST_IP' in os.environ, 'Missing HOST_IP env var'

        os.environ['ROOTCA_DIR'] = self.rootca_dir
        if 'SSL_KEY_LENGTH' not in os.environ:
            os.environ['SSL_KEY_LENGTH'] = '3072'

        os.environ['SAN'] = ('IP:127.0.0.1,DNS:etcd,DNS:ia_configmgr_agent,DNS:*,DNS:localhost,'
                             'URI:urn:unconfigured:application')
        if 'SSL_SAN_IP' not in os.environ:
            os.environ['SSL_SAN_IP'] = ''

        if os.environ['SSL_SAN_IP'] != '':
            os.environ['SAN'] = 'IP:' + os.environ['HOST_IP'] + ',' + 'IP:' + \
                    os.environ['SSL_SAN_IP'] + ',' + os.environ['SAN']
        else:
            os.environ['SAN'] = 'IP:' + os.environ['HOST_IP'] + ',' + \
                    os.environ['SAN']

        if os.environ['ETCD_HOST'] != '':
            pattern = '^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
            match = re.match(pattern, os.environ['ETCD_HOST'])
            if match:
                self.log.info('ETCD_HOST env value is IP')
                os.environ['SAN'] = 'IP:' + \
                                    os.environ['ETCD_HOST'] + ',' + \
                                    os.environ['SAN']
            else:
                self.log.info('ETCD_HOST env value is DNS')
                os.environ['SAN'] = 'DNS:' + \
                                    os.environ["ETCD_HOST"] + ',' + \
                                    os.environ["SAN"]
        os.environ['TLS_CIPHERS'] = (
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,'
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,'
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')

    def _setup_etcd_env(self):
        """Setup environmental variables for ETCD.
        """
        self.log.debug('Setting up ETCD environmental variables')

        assert_env_var('ETCD_PEER_PORT')
        assert_env_var('ETCD_CLIENT_PORT')

        etcd_peer_port = os.environ['ETCD_PEER_PORT']
        etcd_client_port = os.environ['ETCD_CLIENT_PORT']

        if self.dev_mode:
            # ETCD environmental variables in dev mode
            os.environ['ETCD_INITIAL_ADVERTISE_PEER_URLS'] = \
                    f'http://0.0.0.0:{etcd_peer_port}'
            os.environ['ETCD_LISTEN_PEER_URLS'] = \
                    f'http://0.0.0.0:{etcd_peer_port}'
            os.environ['ETCD_LISTEN_CLIENT_URLS'] = \
                    f'http://0.0.0.0:{etcd_client_port}'
            os.environ['ETCD_ADVERTISE_CLIENT_URLS'] = \
                    f'http://0.0.0.0:{etcd_client_port}'
        else:
            # ETCD environmental variables in prod mode
            os.environ['ETCD_INITIAL_ADVERTISE_PEER_URLS'] = \
                f'https://0.0.0.0:{etcd_peer_port}'
            os.environ['ETCD_LISTEN_PEER_URLS'] = \
                    f'https://0.0.0.0:{etcd_peer_port}'
            os.environ['ETCD_LISTEN_CLIENT_URLS'] = \
                    f'https://0.0.0.0:{etcd_client_port}'
            os.environ['ETCD_ADVERTISE_CLIENT_URLS'] = \
                f'https://0.0.0.0:{etcd_client_port}'

            assert_env_var('ETCD_ROOT_PASSWORD')
            os.environ['ETCD_CERT_FILE'] = self.etcd_server_cert
            os.environ['ETCD_KEY_FILE'] = self.etcd_server_key
            os.environ['ETCD_TRUSTED_CA_FILE'] = self.rootca_cert_path
            os.environ['ETCD_CLIENT_CERT_AUTH'] = 'true'
            os.environ['ETCD_PEER_AUTO_TLS'] = 'true'

            os.environ["ETCDCTL_CACERT"] = self.rootca_cert_path
            os.environ["ETCDCTL_CERT"] = self.etcd_client_cert
            os.environ["ETCDCTL_KEY"] = self.etcd_client_key


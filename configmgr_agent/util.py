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

import os
import json
import base64
import subprocess as sp


# Return dict with service:cert_type
def get_cert_type(config_file):
    dict_items = {}
    with open(config_file) as conf_file:
        config = json.load(conf_file)
    for key, value in config.items():
        service_conf = key.split('/')
        if service_conf[2] == 'config':
            if 'cert_type' in value:
                dict_items[service_conf[1]] = list(value['cert_type'])
    return dict_items


def exec_script(script, *args):
    """Helper function to execute in the ./scripts/ directory.
    """
    script = os.path.join('scripts', script)
    cmd = [script] + list(args)

    # assert self.etcd_proc is not None, 'ETCD is not running'
    assert os.path.exists(script), f'Cannot find script: {script}'

    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
            f'{" ".join(cmd)} failed: '
            f'{exc.output.decode("utf-8")}') from exc


def execute_cmd(cmd):
    """Executes the shell cmd

    :param cmd: shell cmd
    :type cmd: str
    """
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
            f'{" ".join(cmd)} failed: '
            f'{exc.output.decode("utf-8")}') from exc


def get_server_cert_key(appname, certtype, certificates_dir_path):
    """ parse appname and certtype, returns server cert and key dict
    :param appname: appname
    :type config: string
    :param certtype: certificate type
    :type apps: string
    :return: server cert key dict
    :rtype: dict
    """
    server_key_cert = {}
    cert_ext = None
    if 'pem' in certtype:
        cert_ext = '.pem'
    elif 'der' in certtype:
        cert_ext = '.der'
    cert_file = certificates_dir_path + '/' + appname + '_Server/' + appname \
        + '_Server_server_certificate' + cert_ext

    key_file = certificates_dir_path + '/' + appname + '_Server/' + appname \
        + '_Server_server_key' + cert_ext
    ca_certificate = certificates_dir_path + '/' + 'rootca/cacert' + cert_ext

    if cert_ext == '.pem':
        with open(cert_file, 'r') as s_cert:
            server_cert = s_cert.read()
            server_key_cert['server_cert'] = server_cert
        with open(key_file, 'r') as s_key:
            server_key = s_key.read()
            server_key_cert['server_key'] = server_key
        with open(ca_certificate, 'r') as cert:
            ca_cert = cert.read()
            server_key_cert['ca_cert'] = ca_cert
    if cert_ext == '.der':
        with open(cert_file, 'rb') as s_cert:
            server_cert = s_cert.read()
            server_key_cert['server_cert'] = \
                base64.standard_b64encode(server_cert).decode('utf-8')
        with open(key_file, 'rb') as s_key:
            server_key = s_key.read()
            server_key_cert['server_key'] = \
                base64.standard_b64encode(server_key).decode('utf-8')
        with open(ca_certificate, 'rb') as cert:
            ca_cert = cert.read()
            server_key_cert['ca_cert'] = \
                base64.standard_b64encode(ca_cert).decode('utf-8')

    return server_key_cert

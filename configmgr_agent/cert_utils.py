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

"""Certificate utilities.
"""
import os
import tempfile
import subprocess as sp


def add_multiple_dns_entries(peer):
    multiple_domain = ''
    if isinstance(peer, list):
        for index, name in enumerate(peer, start=1):
            multiple_domain += 'DNS.' + str(index+1) + '=' + name
            multiple_domain += '\n'
    else:
        multiple_domain = 'DNS.2=' + peer
        multiple_domain += '\n'
    return multiple_domain


def generate_openssl_cnf(
        common_name, client_alt_name, server_alt_name, cnf_template):
    """Generate OpenSSL CNF file.
    """
    assert os.path.exists(cnf_template), f'{cnf_template} does not exist'

    cli_domains = ''
    server_domains = ''
    tmp_cnf_fn = None

    if client_alt_name is not None:
        cli_domains = add_multiple_dns_entries(client_alt_name)

    if server_alt_name is not None:
        server_domains = add_multiple_dns_entries(server_alt_name)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as outfile:
        with open(cnf_template, 'r') as infile:
            in_cnf = infile.read()
            out_cnf0 = in_cnf.replace('@COMMON_NAME@', common_name)
            out_cnf1 = out_cnf0.replace('@MULTIPLE_CLI_DOMAINS@', cli_domains)
            out_cnf2 = out_cnf1.replace('@MULTIPLE_SERVER_DOMAINS@',
                                        server_domains)
            outfile.write(out_cnf2)
            tmp_cnf_fn = outfile.name

    return tmp_cnf_fn


def openssl_req(cnf_fn, *args, **kwargs):
    """Execute the openssl req command.
    """
    cmd = ['openssl', 'req', '-config', cnf_fn] + list(args)
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
                f'openssl req failed:\n{exc.output.decode("utf-8")}') from exc


def openssl_x509(*args, **kwargs):
    """Execute the openssl x509 command.
    """
    cmd = ['openssl', 'x509'] + list(args)
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
                f'openssl x509 failed:\n{exc.output.decode("utf-8")}') from exc


def openssl_ca(cnf_path, *args, **kwargs):
    """Execute openssl ca command.
    """
    cmd = ['openssl', 'ca', '-config', cnf_path] + list(args)
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
                f'openssl ca failed:\n{exc.output.decode("utf-8")}') from exc

def openssl_rsa(*args, **kwargs):
    cmd = ['openssl', 'rsa'] + list(args)
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as exc:
        raise RuntimeError(
                f'openssl RSA failed:\n{exc.output.decode("utf-8")}') from exc

def generate_root_ca(
        common_name, key_path, cert_path, cert_cer_path,
        client_alt_name=None, server_alt_name=None, ssl_key_length=3072,
        cnf_template='config/openssl.cnf'):
    """Generate the rootca certificate.
    """
    cnf_path = generate_openssl_cnf(
            common_name, client_alt_name, server_alt_name, cnf_template)
    try:
        openssl_req(cnf_path,
                    '-x509',
                    '-days',    '3650',
                    '-newkey',  f'rsa:{ssl_key_length}',
                    '-keyout',  key_path,
                    '-out',     cert_path,
                    '-outform', 'PEM',
                    '-subj',    '/CN=EIICertToolSelfSignedtRootCA/L=$$$$/',
                    '-nodes')
        openssl_x509('-in',      cert_path,
                     '-out',     cert_cer_path,
                     '-outform', 'DER')
    finally:
        # Delete the CNF file
        os.remove(cnf_path)

def generate_cert_key_pair(
        key, peer, opts, base_dir, private_key_path, cert_path, client_alt_name,
        server_alt_name, req_pem_path, pa_cert_path, pa_key_path,
        pa_certs_path, ssl_key_length=3072, cnf_template='config/openssl.cnf'):
    """Generate certificate and key pair.
    """
    cnf_path = generate_openssl_cnf(
            key, client_alt_name, server_alt_name, cnf_template)

    try:
        openssl_req(cnf_path,
                    '-new',
                    '-newkey',  f'rsa:{ssl_key_length}',
                    '-keyout',  private_key_path,
                    '-out',     req_pem_path,
                    '-days',    '3650',
                    '-outform', 'PEM',
                    '-subj',    f'/CN={key}/O={peer}/L=$$$/',
                    '-nodes')
        if key not in ['OpcuaExport_Server', 'opcua']:
            openssl_ca(cnf_path,
                    '-days',    '3650',
                    '-cert',    pa_cert_path,
                    '-keyfile', pa_key_path,
                    '-in',      req_pem_path,
                    '-out',     cert_path,
                    '-outdir',  pa_certs_path,
                    '-notext',
                    '-batch',
                    '-extensions', f'{peer}_extensions')
        if 'output_format' in opts and opts['output_format'] == 'DER':
            if key not in ['OpcuaExport_Server', 'opcua']:
                openssl_x509('-in',      cert_path,
                            '-out',     f'{base_dir}_{peer}_certificate.der',
                            '-outform', 'DER')
                openssl_rsa('-in',  private_key_path,
                            '-out', f'{base_dir}_{peer}_key.der',
                            '-inform', 'PEM',
                            '-outform', 'DER')
            else:
                openssl_x509('-in',      req_pem_path,
                            '-out',     f'{base_dir}_{peer}_certificate.der',
                            '-outform', 'DER')
                openssl_rsa('-in',  private_key_path,
                            '-out', f'{base_dir}_{peer}_key.der',
                            '-inform', 'PEM',
                            '-outform', 'DER')
    finally:
        # Delete CNF file
        os.remove(cnf_path)

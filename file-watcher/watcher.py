"""Watch a file for its existence or lack there of.
"""
import os
import sys
import time
import argparse
import etcd3


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Parse arguments
ap = argparse.ArgumentParser()
ap.add_argument('files', nargs='+', help='File(s) to watch')
ap.add_argument('-i', '--interval', type=float, default=0.25,
                help='Poll interval to check the file\'s status')
args = ap.parse_args()

try:
    prev_exists = dict([(f, None) for f in args.files])
    break_out = False
    while True:
        for f in args.files:
            exists = os.path.exists(f)
            if exists != prev_exists[f]:
                prev_exists[f] = exists
                if exists:
                    eprint(f'[INFO] File "{f}" exists')
                    break_out = True
                else:
                    eprint(f'[INFO] File "{f}" does not exist')
        if break_out:
            break
        time.sleep(args.interval)

    eprint('[INFO] Sleeping 10s')
    time.sleep(10)

    eprint('[INFO] Attempting connection to ETCD')
    client = etcd3.client(
            host='127.0.0.1', port=2379,
            ca_cert='/Certificates/rootca/cacert.pem',
            cert_key='/Certificates/file-watcher/file-watcher_client_key.pem',
            cert_cert='/Certificates/file-watcher/file-watcher_client_certificate.pem')

    eprint('[INFO] Attempting to put values')
    client.put('/etcd_ui/test', 'hello world')

    eprint('[INFO] Getting all values')
    for key, value in client.get_prefix('/etcd_ui/'):
        eprint(f'[INFO] KEY: {key} - VALUE: {value}')
except KeyboardInterrupt:
    eprint('[INFO] Quitting...')

#!/bin/bash

# Copyright (c) 2020 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#Script to write back data from ETCD Cluster to JSON file.
function helpFunction {
    echo >&2
    echo "Usage: ./etcd_capture.sh --ca_etcd ca_certificate --etcd_root_cert root_cert --etcd_root_key root_key --etcd_endpoints etcd_host:port" >&2
    echo >&2
    echo "SUMMARY": >&2
    echo >&2
    echo "  --ca_etcd  etcd ca certificate" >&2
    echo >&2
    echo "  --etcd_root_cert  root client certificate" >&2
    echo >&2
    echo "  --etcd_root_key  root client key" >&2
    echo >&2
    echo "  --etcd_endpoints  etcd_host:port" >&2
    echo >&2
    exit 1
}

function etcdCapture {
    mkdir -p data/etcd_capture
    python3 scripts/etcd_capture.py $@
    echo "etcd captured data will be found at $EII_INSTALL_PATH/data/etcd_capture_data.json"
}

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    helpFunction
fi
etcdCapture $@

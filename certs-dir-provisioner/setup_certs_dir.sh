#!/bin/bash

RED='\033[0;31m'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
NC='\033[0m' # No Color

function log_warn() {
    echo -e "${YELLOW}WARN: $1 ${NC}"
}

function log_info() {
    echo -e "${GREEN}INFO: $1 ${NC}"
}

function log_error() {
    echo -e "${RED}ERROR: $1 ${NC}"
}

function log_fatal() {
    echo -e "${RED}FATAL: $1 ${NC}"
    exit -1
}

function check_error() {
    if [ $? -ne 0 ] ; then
        if [ -f "rm /tmp/cmake-3.11.1-Linux-x86_64.sh" ] ; then
            rm /tmp/cmake-3.11.1-linux-x86_64.sh
        fi
        log_fatal "$1"
    fi
}

if [[ -z "${SERVICES}" ]] ; then
    log_fatal "SERVICES environmental variable is missing"
fi

for service in $(echo $SERVICES | sed "s/,/ /g") ; do
    certs_dir=/Certificates/$service
    if [ ! -d "$certs_dir" ] ; then
        log_info "Creating service certs directory: $certs_dir"
        mkdir -p $certs_dir
        check_error "Failed to create service certs directory: $certs_dir"
    else
        log_info "$certs_dir already exists"
    fi
done

log_info "Done."

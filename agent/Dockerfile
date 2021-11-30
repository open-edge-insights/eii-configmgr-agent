# Configuration daemon Dockerfile

FROM ubuntu:18.04

# Setting python dev env
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common curl && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends python3.6 \
                                               python3-pip && \
    python3.6 -m pip install -U pip && \
    ln -sf /usr/bin/pip /usr/bin/pip3

RUN  apt update && \
     apt install -y curl

RUN pip3 install --upgrade pip
RUN pip3 install setuptools

RUN mkdir -p /EII/etcd/data
RUN mkdir -p /EII/Certificates

ENV http_proxy http://proxy.iind.intel.com:911
ENV https_proxy http://proxy.iind.intel.com:911

ARG ETCD_VERSION
RUN curl -L https://github.com/coreos/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz -o /EII/etcd-${ETCD_VERSION}-linux-amd64.tar.gz && \
    tar -xvf /EII/etcd-${ETCD_VERSION}-linux-amd64.tar.gz -C /EII/etcd --strip 1 && \
    rm -f /EII/etcd-${ETCD_VERSION}-linux-amd64.tar.gz

WORKDIR /EII/etcd/

COPY requirements.txt .
RUN pip3 install -r requirements.txt
USER root
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY configd/ ./configd/
COPY agent.py .
RUN export PYTHONPATH=$PYTHONPATH:./configd
ENTRYPOINT ["python3", "-u", "agent.py", "-d", "/EII/Certificates", "-l", "DEBUG"]

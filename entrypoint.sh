#!/bin/sh

chown -R $EIIUSER:$EIIUSER /EII/Certificates
chown -R $EIIUSER:$EIIUSER /EII/etcd
chmod -R 760 /EII/Certificates
chmod -R 760 /EII/etcd
exec runuser -u $EIIUSER -- $@

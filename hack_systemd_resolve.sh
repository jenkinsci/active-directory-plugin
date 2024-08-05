#!/bin/bash

# the FlintsonesIT will not work if the the DNS ports can not be bound
# usually because you are running a DNS server locally (but why!)
# for some ungodly known reason this appears to the default on some systemd installations

systemctl stop systemd-resolved
sed -i 's/#DNS=.*/DNS=8.8.8.8/g' /etc/systemd/resolved.conf
sed -i 's/DNSStubListener=yes/DNSStubListener=no/g' /etc/systemd/resolved.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl start systemd-resolved

#!/bin/bash
set -x
# the FlintsonesIT will not work if the the DNS ports can not be bound
# usually because you are running a DNS server locally (but why!)
# for some ungodly known reason this appears to the default on some systemd installations

# uses instructions from https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html

lsof -i :53
systemctl stop systemd-resolved
lsof -i :53
sed -i 's/#DNS=.*/DNS=8.8.8.8/g' /etc/systemd/resolved.conf
sed -i 's/DNSStubListener=yes/DNSStubListener=no/g' /etc/systemd/resolved.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
lsof -i :53
systemctl start systemd-resolved
lsof -i :53

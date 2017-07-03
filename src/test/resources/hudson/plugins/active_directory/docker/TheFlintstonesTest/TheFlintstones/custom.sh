#!/bin/bash

#
# Custom script to add users, groups and add users to groups
#

# add groups
samba-tool group add The-Flintstones

# add users
samba-tool user add Fred ia4uV1EeKait
samba-tool user add Wilma ia4uV1EeKait


# add users to groups
samba-tool group addmembers The-Flintstones Fred
samba-tool group addmembers The-Flintstones Wilma

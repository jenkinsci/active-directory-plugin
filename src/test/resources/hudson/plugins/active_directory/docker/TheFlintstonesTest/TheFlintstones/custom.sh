#!/bin/bash

#
# Custom script to add users, groups and add users to groups
#

# add groups
samba-tool group add The-Flintstones
samba-tool group add "The Rubbles"

# add users
samba-tool user add Fred ia4uV1EeKait
samba-tool user add Wilma ia4uV1EeKait
samba-tool user add Barney ia4uV1EeKait
samba-tool user add Betty ia4uV1EeKait
samba-tool user add Dino p1bfdrMsqyHhbAm

# add users to groups
samba-tool group addmembers The-Flintstones Fred
samba-tool group addmembers The-Flintstones Wilma
samba-tool group addmembers The-Flintstones Dino
samba-tool group addmembers "The Rubbles" Barney

# add alias for the "The Rubbles"
{ cat > file.ldif <<-EOF
dn: CN=The Rubbles,cn=Users,dc=samdom,dc=example,dc=com
changetype: modify
replace: sAMAccountName
sAMAccountName: Rubbles
EOF
} && ldapmodify -a -h 127.0.0.1 -p 389 -D "cn=Administrator,cn=Users,dc=samdom,dc=example,dc=com" -w "ia4uV1EeKait" -f file.ldif

# add Betty to Rubbles alias
samba-tool group addmembers Rubbles Betty

#!/bin/sh
# Seed data. Passwords: users "Test-Password-123", cn=ldapm-admin "ldapm-admin-secret".
# Size limit is 25 and there are 30+ users, so listing them needs paged results.
set -eu
B=dc=example,dc=org
pw=$(slappasswd -s 'Test-Password-123')
adminpw=$(slappasswd -s 'ldapm-admin-secret')

cat <<LDIF
dn: $B
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: cn=ldapm-admin,$B
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: ldapm-admin
userPassword: $adminpw

dn: ou=people,$B
objectClass: organizationalUnit
ou: people

dn: ou=groups,$B
objectClass: organizationalUnit
ou: groups

dn: ou=policies,$B
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,$B
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMinLength: 12
pwdCheckQuality: 2
pwdLockout: TRUE
pwdMaxFailure: 3
pwdLockoutDuration: 120
pwdFailureCountInterval: 300
pwdInHistory: 3
pwdMinAge: 0
pwdMustChange: FALSE
pwdAllowUserChange: TRUE

dn: cn=service,ou=policies,$B
objectClass: device
objectClass: pwdPolicy
cn: service
pwdAttribute: userPassword
pwdMinLength: 20
pwdCheckQuality: 2
pwdLockout: FALSE

LDIF

n=10000
user() { # uid given sn [extra ldif lines]
  n=$((n + 1)); uid=$1; given=$2; sn=$3; shift 3
  cat <<LDIF
dn: uid=$uid,ou=people,$B
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: $uid
givenName: $given
sn: $sn
cn: $given $sn
mail: $uid@example.org
uidNumber: $n
gidNumber: 20000
homeDirectory: /home/$uid
loginShell: /bin/bash
userPassword: $pw
LDIF
  for line in "$@"; do echo "$line"; done
  echo
}

user jdoe John Doe "jpegPhoto:: /9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP8="
user asmith Anna Smith
user mlocked Mikel Locked "pwdAccountLockedTime: 000001010000Z"
user svc-backup Backup Service "pwdPolicySubentry: cn=service,ou=policies,$B"
# UTF-8 cn exercises base64 LDIF values.
n=$((n + 1))
cat <<LDIF
dn: uid=ietxeberria,ou=people,$B
objectClass: inetOrgPerson
objectClass: posixAccount
uid: ietxeberria
givenName:: $(printf 'Iñaki' | base64)
sn: Etxeberria
cn:: $(printf 'Iñaki Etxeberria' | base64)
mail: ietxeberria@example.org
uidNumber: $n
gidNumber: 20000
homeDirectory: /home/ietxeberria
loginShell: /bin/bash
userPassword: $pw

LDIF
# Not a posixAccount: plain inetOrgPerson, as many directories create users.
cat <<LDIF
dn: uid=contractor,ou=people,$B
objectClass: inetOrgPerson
uid: contractor
givenName: Carla
sn: Contractor
cn: Carla Contractor
mail: contractor@example.org
userPassword: $pw

LDIF
i=1
while [ $i -le 30 ]; do
  user "$(printf 'user%02d' $i)" User "$(printf 'Number%02d' $i)"
  i=$((i + 1))
done

group() { # cn gid members...
  cn=$1; gid=$2; shift 2
  printf 'dn: cn=%s,ou=groups,%s\nobjectClass: posixGroup\ncn: %s\ngidNumber: %s\n' "$cn" "$B" "$cn" "$gid"
  for m in "$@"; do echo "memberUid: $m"; done
  echo
}
group staff 20000
# "ghost" has no user entry: a dangling reference.
group devs 20010 asmith jdoe ghost
group vpn 20020 jdoe ietxeberria
group admins 20030 asmith
group empty 20040

# RFC 4519 groups with DN-valued members: a nested group, a dangling DN,
# and a uniqueMember with the optional #'…'B identifier.
cat <<LDIF
dn: cn=project-x,ou=groups,$B
objectClass: groupOfNames
cn: project-x
description: Project team
member: uid=jdoe,ou=people,$B
member: uid=contractor,ou=people,$B
member: uid=gone,ou=people,$B
member: cn=devs,ou=groups,$B

dn: cn=auditors,ou=groups,$B
objectClass: groupOfUniqueNames
cn: auditors
uniqueMember: uid=asmith,ou=people,$B
uniqueMember: uid=contractor,ou=people,$B#'0101'B
LDIF

# Test directory

A disposable OpenLDAP for development and end-to-end tests. Nothing here is
suitable for production.

```sh
./run.sh up        # generate certs (once), build and start containers
./run.sh profiles  # write test profiles into testdir/.config, print the export line
./run.sh logs
./run.sh reset     # wipe data and start fresh
./run.sh down
```

If the image builds fail to resolve package mirrors (Docker without DNS for
builds), run with `LDAPM_BUILD_NETWORK=host ./run.sh up`.

## Containers

| Service | Image base | Ports on 127.0.0.1 |
|---|---|---|
| `slapd` | Debian 13, OpenLDAP 2.6 | 6360 (ldaps), 3890 (ldap + StartTLS) |
| `bastion` | Debian 12, OpenSSH | 2222 (user `tunnel`, key auth only) |

Inside the compose network the directory is also reachable as `ldap.test`,
which is in the server certificate but not resolvable from the host. The
`test-tunnel` profile uses it, so a passing tunnel test proves traffic went
through SSH and TLS verified the real host name.

## Certificates (`certs/`, generated, git-ignored)

| File | Purpose |
|---|---|
| `ca.pem` | Test CA; pin this in profiles |
| `server.pem` | SANs `ldap.test`, `localhost`, `127.0.0.1` |
| `other-ca.pem` | Unrelated CA for negative TLS tests |
| `bastion_ed25519` | SSH key for the bastion |
| `known_hosts` | Bastion host key, written by `run.sh profiles` |

## Directory content

| Entry | Notes |
|---|---|
| `cn=ldapm-admin,dc=example,dc=org` | Bind DN, password `ldapm-admin-secret`, write access everywhere, `size.prtotal=unlimited` |
| `cn=admin,dc=example,dc=org` | Root DN, password `admin-secret`; ldapm should never use it |
| `ou=people` | 36 users, password `Test-Password-123` |
| `uid=jdoe` | Has a binary `jpegPhoto`; member of devs and vpn |
| `uid=mlocked` | Permanently locked (`pwdAccountLockedTime: 000001010000Z`) |
| `uid=svc-backup` | Service policy via `pwdPolicySubentry` |
| `uid=ietxeberria` | UTF-8 `cn` (base64 in LDIF) |
| `uid=contractor` | Plain `inetOrgPerson`, no posix attributes |
| `uid=user01` … `user30` | Bulk users; more than the size limit of 25 |
| `ou=groups` | `posixGroup`: `staff` (primary, 20000), `devs` (contains dangling `ghost`), `vpn`, `admins`, `empty` |
| | `groupOfNames` `project-x`: jdoe, contractor, the group `devs`, dangling `uid=gone` |
| | `groupOfUniqueNames` `auditors`: asmith, contractor (with `#'0101'B`) |
| `ou=policies` | `cn=default` (min length 12, quality 2, lockout after 3 failures) and `cn=service` (min length 20, no lockout) |

The global size limit is 25 so paged results are always exercised.

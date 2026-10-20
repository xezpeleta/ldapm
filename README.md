# ldapm

**A safe, scriptable command-line tool for browsing LDAP directories.**

`ldapm` answers everyday directory questions — *who is this user, which groups
are they in, is the account locked, which group members no longer exist* — in
one short command, with output that is pleasant for people and stable JSON for
scripts and AI agents.

```console
$ ldapm user show jdoe
dn:           uid=jdoe,ou=people,dc=example,dc=org
cn:           John Doe
mail:         jdoe@example.org
uidNumber:    10001
gidNumber:    20000
groups:       staff (primary), devs, project-x, vpn
status:       active
policy:       default
pwdReset:     no
pwdChanged:   -
failed binds: 0

$ ldapm group show devs
dn:          cn=devs,ou=groups,dc=example,dc=org
cn:          devs
objectClass: posixGroup
gidNumber:   20010
description: -
members:     3 (1 dangling)
  asmith
  ghost   ! no such user
  jdoe
```

Why not just `ldapsearch`?

- **Pinned TLS.** Each connection profile trusts exactly one CA certificate.
  No system trust store, no "ignore certificate" switch, no plain LDAP.
- **No secrets in the wrong places.** Bind passwords are never accepted as
  arguments or environment variables, never written to config files and never
  logged. You type them, pipe them, or keep them in your desktop keyring.
- **SSH tunnels built in.** Reach a directory behind a bastion host with a
  pinned SSH host key; TLS is still verified against the real server name.
- **Understands common directory layouts.** POSIX users and groups, RFC 4519
  `groupOfNames`/`groupOfUniqueNames`, OpenLDAP password policy (ppolicy)
  lockouts, dangling member references, paged results past server size limits.
- **Read-only.** This version cannot modify your directory. Password values are
  hidden even when the server would return them.

> **Status:** 0.1 — read-only. Write commands (password reset, lock/unlock,
> user and group changes) are planned, always as *preview → confirm → apply*.

---

## Install

`ldapm` is a single static binary for Linux (x86_64 and arm64). It needs no
runtime libraries.

**Prebuilt binary** (recommended):

```sh
mkdir -p ~/.local/bin
curl -fsSL https://github.com/xezpeleta/ldapm/releases/latest/download/ldapm-x86_64-unknown-linux-musl.tar.gz \
  | tar xz -C ~/.local/bin ldapm
ldapm --version
```

On arm64, replace `x86_64` with `aarch64`. Each archive has a `.sha256` file
next to it on the [releases page](https://github.com/xezpeleta/ldapm/releases)
if you want to verify the download. Make sure `~/.local/bin` is on your `PATH`
(it is by default on Ubuntu and Fedora).

**From source** (Rust ≥ 1.90 and a C compiler, e.g. `build-essential`):

```sh
cargo install --locked --git https://github.com/xezpeleta/ldapm ldapm
```

**Optional:**

- `ssh` (OpenSSH client), only for profiles that use a tunnel.
- A Secret Service keyring (GNOME Keyring, KWallet, KeePassXC), only if you
  want `ldapm` to remember bind passwords.

---

## Quick start

You need four things from your directory: its **host name**, the **CA
certificate** that signed its TLS certificate (a PEM file), a **bind DN** to
log in with, and the **base DN**.

> **Getting the CA certificate:** ask your directory administrator, or copy the
> file named by `olcTLSCACertificateFile` on an OpenLDAP server. Avoid
> downloading it from the server you are about to trust.

**1. Create a profile.** The CA file is copied into ldapm's config directory.

```sh
ldapm profile add work \
  --host ldap.example.org \
  --ca ~/Downloads/example-ca.pem \
  --bind-dn cn=reader,dc=example,dc=org \
  --base-dn dc=example,dc=org \
  --default
```

Use `--starttls` if the server only offers StartTLS on port 389 instead of
LDAPS on port 636.

**2. Test it.** Every step is checked separately, so a failure points at the
right layer:

```console
$ ldapm profile test
✓ CA file /home/me/.config/ldapm/ca/work.pem (1 certificate)
✓ TLS (ldaps) verified against the pinned CA, hostname ldap.example.org
Bind password for cn=reader,dc=example,dc=org:
✓ Bound as dn:cn=reader,dc=example,dc=org
✓ base DN dc=example,dc=org readable
✓ people base ou=people,dc=example,dc=org readable
✓ groups base ou=groups,dc=example,dc=org readable
✓ 7 groups found
✓ 36 users found
```

If your users or groups live somewhere else, `profile test` says so and
suggests the fix (see [Directory layouts](#directory-layouts)).

**3. Use it.**

```sh
ldapm whoami                       # who the server thinks you are
ldapm user search smith            # find users by uid, name or mail
ldapm user show asmith             # one user: groups, lock state, password policy
ldapm group list                   # all groups with member counts
ldapm group show devs              # members, with dangling references flagged
ldapm entry ls                     # browse the tree one level at a time
ldapm entry show uid=asmith,ou=people,dc=example,dc=org -o   # all attributes, incl. operational
```

**Optional: remember the password.** By default you are asked every time. To
store it in your desktop keyring (it is verified first):

```sh
ldapm profile edit work --remember-password
ldapm profile edit work --forget-password    # undo
```

---

## Commands

```
ldapm whoami
ldapm profile  list | show [name] | add <name> | edit <name> | rm <name> | test [name]
ldapm entry    ls [dn] | show <dn> [-o] | search <term> [--base <dn>] [--by uid|cn|mail|any]
ldapm user     show <uid> | search <term>
ldapm group    list | show <cn>
```

| Global flag | Meaning |
|---|---|
| `-p, --profile <name>` | Profile to use. Default: `$LDAPM_PROFILE`, then the profile marked default, then the only profile. |
| `--json` | JSON on stdout; errors as JSON on stderr. |
| `--password-stdin` | Read the bind password from the first line of stdin. |
| `-v`, `-vv` | Diagnostic logs on stderr. Passwords never appear in them. |

Every command has `--help`, e.g. `ldapm profile add --help`.

### What the output means

- **`status`** comes from the OpenLDAP password policy overlay:
  `active`, `disabled` (an administrator lock, `pwdAccountLockedTime:
  000001010000Z`), or `locked out` (too many failed binds, with the time it
  ends). On servers without ppolicy every account shows as `active`.
- **`policy`** is the account's `pwdPolicySubentry`, or `default` when the
  server's default policy applies.
- **`! no such user` / `! no such entry`** marks a group member that points at
  nothing: a `memberUid` with no matching user, or a `member`/`uniqueMember`
  DN that does not exist.
- **`+`** after a name in `entry ls` means the entry has children.
- `userPassword` and similar attributes are always shown as `<hidden>`; binary
  values (photos, certificates) as `<binary, N bytes>`.

---

## Directory layouts

`ldapm` works out of the box with the most common layout:

```
dc=example,dc=org
├── ou=people     users
└── ou=groups     groups
```

**Recognised object classes** (no configuration needed):

| | Object classes | Membership |
|---|---|---|
| Users | `inetOrgPerson`, `organizationalPerson`, `person`, `posixAccount` | — |
| Groups | `posixGroup` (RFC 2307) | `memberUid` (uid) and primary group via `gidNumber` |
| | `groupOfNames` (RFC 4519) | `member` (DN) |
| | `groupOfUniqueNames` (RFC 4519) | `uniqueMember` (DN) |

Mixed directories (some POSIX groups, some DN-based groups, rfc2307bis groups
with both) work as well. Users are looked up by `uid`.

**Other locations.** Point the profile at your containers:

```sh
# 389 Directory Server / many OpenLDAP installs: ou=People, ou=Groups (case does not matter)
ldapm profile edit work --people-base ou=People,dc=example,dc=org --groups-base ou=Groups,dc=example,dc=org

# FreeIPA
ldapm profile edit ipa --people-base cn=users,cn=accounts,dc=example,dc=org \
                       --groups-base cn=groups,cn=accounts,dc=example,dc=org

# Users spread over several OUs: use the parent; searches go down the whole subtree
ldapm profile edit work --people-base dc=example,dc=org
```

**Other object classes.** Override which entries count as users or groups with
any LDAP filter:

```sh
ldapm profile edit work --user-filter '(objectClass=posixAccount)'           # only POSIX accounts
ldapm profile edit work --user-filter '(|(objectClass=person)(objectClass=account))'
ldapm profile edit work --group-filter '(objectClass=groupOfNames)'
```

`ldapm profile show` prints the values in effect.

---

## For scripts and AI agents

`ldapm` is designed to be driven by programs. The rules:

1. **Always pass `--json`.** stdout then carries exactly one JSON document;
   nothing else is printed there. Field names are `snake_case` and only grow
   (new fields may appear; existing ones keep their meaning).
2. **Authenticate without a terminal.** Either opt in to the keyring once
   (`ldapm profile edit <name> --remember-password`, done by a human), or pipe
   the password: `secret-tool lookup ldap reader | ldapm --password-stdin --json …`.
   Without either, ldapm fails with exit code 1 instead of hanging on a prompt.
   There is deliberately no password flag or environment variable.
3. **Check the exit code**, then parse stderr on failure:

   | Exit | Meaning |
   |---|---|
   | 0 | Success |
   | 1 | Usage or local problem; nothing was sent to the server (bad arguments, unknown profile, invalid filter, no password available) |
   | 2 | Directory problem: connection, TLS, tunnel, LDAP error, or not found |

   With `--json`, the error is one line of JSON on stderr:

   ```json
   {"error":{"code":"not_found","message":"user \"nobody\" not found","ldap_code":null,"exit_code":2}}
   ```

   `code` is one of `config`, `profile_not_found`, `invalid_input`, `ca_cert`,
   `tls`, `connect`, `tunnel`, `ldap`, `server`, `not_found`, `size_limit`,
   `keyring`, `io`. `ldap_code` is the LDAP result code for `server` errors
   (e.g. `49` invalid credentials, `50` insufficient access).

4. **Select the profile explicitly** with `-p <name>` or `LDAPM_PROFILE`.

**Output shapes** (abridged):

```jsonc
// ldapm --json whoami
{"profile":"work","authz_id":"dn:cn=reader,dc=example,dc=org","url":"ldaps://ldap.example.org:636","tls":"ldaps","tunnel":false}

// ldapm --json user show jdoe
{"dn":"uid=jdoe,ou=people,dc=example,dc=org","uid":"jdoe","cn":"John Doe","mail":"jdoe@example.org",
 "uid_number":"10001","gid_number":"20000",
 "groups":[{"dn":"cn=staff,ou=groups,dc=example,dc=org","cn":"staff","primary":true}],
 "status":{"state":"active"},      // or {"state":"disabled"} or {"state":"locked_out","since":"…Z","until":"…Z"}
 "policy":null,"pwd_reset":false,"pwd_changed":null,"failed_binds":0}

// ldapm --json user search doe      and      ldapm --json entry search doe
[{"dn":"uid=jdoe,ou=people,dc=example,dc=org","uid":"jdoe","cn":"John Doe","mail":"jdoe@example.org"}]

// ldapm --json group list
[{"dn":"cn=devs,ou=groups,dc=example,dc=org","cn":"devs","gid_number":"20010","member_count":3}]

// ldapm --json group show devs
{"dn":"cn=devs,ou=groups,dc=example,dc=org","cn":"devs","object_classes":["posixGroup"],
 "gid_number":"20010","description":null,
 "members":[{"value":"ghost","attr":"memberUid","exists":false}]}   // attr: memberUid | member | uniqueMember

// ldapm --json entry ls ou=groups,dc=example,dc=org
{"nodes":[{"dn":"cn=devs,ou=groups,dc=example,dc=org","rdn":"cn=devs","has_children":false,"object_classes":["posixGroup"]}],
 "truncated":false}

// ldapm --json entry show <dn> [-o]
{"dn":"…","attrs":[{"name":"cn","values":[{"type":"text","value":"John Doe"}]},
                   {"name":"jpegPhoto","values":[{"type":"binary","len":18342}]},
                   {"name":"userPassword","values":[{"type":"hidden"}]}]}

// ldapm --json profile list
[{"name":"work","default":true,"url":"ldaps://ldap.example.org:636","tunnel":null,"remember_password":true}]
```

Values that may be missing are `null`. `profile test` is meant for people and
has no JSON form; use `whoami` as a connectivity check in scripts.

**Snippet for your agent instructions** (`AGENTS.md`, `CLAUDE.md`, …):

```markdown
## LDAP directory
Use the `ldapm` CLI (read-only) for directory lookups. Always pass `--json` and `-p <profile>`.
- Find users: `ldapm -p work --json user search <term>`; details: `ldapm -p work --json user show <uid>`
- Groups: `ldapm -p work --json group list`, `ldapm -p work --json group show <cn>`
- Raw entries: `ldapm -p work --json entry search <term>`, `entry ls <dn>`, `entry show <dn> -o`
Exit 0 = ok, 1 = local/usage problem, 2 = directory problem; on failure read the JSON `error` on stderr.
Never ask for, print or pass the bind password; the profile already has it in the keyring.
```

---

## SSH tunnel

For a directory that is only reachable through a jump host:

```sh
ldapm profile add internal \
  --host ldap.internal.example.org --ca ~/certs/internal-ca.pem \
  --bind-dn cn=reader,dc=example,dc=org --base-dn dc=example,dc=org \
  --ssh admin@bastion.example.org \
  --ssh-identity ~/.ssh/id_ed25519 \
  --ssh-known-hosts ~/.config/ldapm/known_hosts
```

`ldapm` runs your system `ssh` with strict host key checking and batch mode,
so the jump host's key must already be in the known-hosts file and the key
must work without a passphrase prompt (use `ssh-agent`). `--host` is the
directory's name as seen from the jump host; it must match the server
certificate. Each command opens and closes its own tunnel.

---

## Configuration files

| Path | Content |
|---|---|
| `~/.config/ldapm/profiles.toml` | Profiles. Never contains passwords. |
| `~/.config/ldapm/ca/<profile>.pem` | The pinned CA certificate of each profile. |
| Secret Service, service `ldapm` | Bind passwords, only for profiles with `--remember-password`. |

Set `LDAPM_CONFIG_DIR` to use a different directory. The file can be edited by
hand; ldapm validates it on load:

```toml
default = "work"

[profiles.work]
host = "ldap.example.org"
port = 636                         # optional; 636 for ldaps, 389 for starttls
scheme = "ldaps"                   # "ldaps" or "starttls"
ca = "ca/work.pem"                 # relative to the config directory, or absolute
bind_dn = "cn=reader,dc=example,dc=org"
base_dn = "dc=example,dc=org"
remember_password = false

[profiles.work.ssh]                # optional
target = "admin@bastion.example.org"
port = 22
identity = "/home/me/.ssh/id_ed25519"
known_hosts = "/home/me/.config/ldapm/known_hosts"

[profiles.work.conventions]        # optional; defaults shown
people_base = "ou=people,dc=example,dc=org"
groups_base = "ou=groups,dc=example,dc=org"
user_filter = "(|(objectClass=person)(objectClass=posixAccount))"
group_filter = "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
```

---

## Server-side notes

- **Use a dedicated, least-privileged bind account** with read access to the
  people and groups subtrees. Never the root DN (`olcRootDN`): it bypasses
  every ACL and the password policy.
- **Size limits.** Large directories may stop a search at the server's size
  limit (OpenLDAP default: 500). ldapm uses paged results, but OpenLDAP still
  caps paged totals unless the bind DN is allowed more, e.g.
  `olcLimits: dn.exact="cn=reader,dc=example,dc=org" size.prtotal=unlimited`.
  ldapm reports the limit explicitly rather than showing partial results (only
  `entry ls` shows a partial level, marked `truncated`).
- **Password policy attributes** (`pwdAccountLockedTime`, `pwdFailureTime`, …)
  are operational; your bind account needs read access to them for `status`
  to be accurate.

## Limitations

- Linux only for now (the keyring integration uses the freedesktop Secret
  Service). Read-only.
- Lock state is read from OpenLDAP's ppolicy overlay. Active Directory and
  other servers that use different attributes (`userAccountControl`,
  `nsAccountLock`) are not interpreted; users are matched by `uid`, not
  `sAMAccountName`.
- `user show` finds memberships by exact DN. A `uniqueMember` value carrying
  the optional `#'…'B` identifier is resolved by `group show` but not matched
  by `user show` (LDAP's `uniqueMemberMatch` rule does not allow it).
- Each command opens a new connection (and tunnel), about half a second per
  command on a LAN.

---

## Development

```sh
cargo build                      # needs a C compiler for the `ring` crypto library
cargo test                       # unit and offline tests
```

No C toolchain on your machine? `./scripts/cargo <args>` runs the same cargo
command inside a Docker container.

End-to-end tests run against a disposable OpenLDAP 2.6 with ppolicy and an SSH
bastion in Docker (see [`testdir/README.md`](testdir/README.md)):

```sh
testdir/run.sh up
LDAPM_TESTDIR=1 cargo test
eval "$(testdir/run.sh profiles | tail -1)"   # try the CLI against it
target/debug/ldapm user show jdoe             # password: ldapm-admin-secret
testdir/run.sh down
```

The code is split into `crates/ldapm-core` (all directory logic) and
`crates/ldapm-cli` (argument parsing and output only).

## License

Copyright (C) 2026 The ldapm contributors.

ldapm is free software: you can redistribute it and/or modify it under the
terms of the [GNU General Public License, version 3](LICENSE), as published by
the Free Software Foundation. It is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; see the license for details.

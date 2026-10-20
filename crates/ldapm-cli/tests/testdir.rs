//! End-to-end tests against the Docker directory in `testdir/`.
//!
//! Start it with `testdir/run.sh up`, then run `cargo test` with
//! `LDAPM_TESTDIR=1`. Without that variable these tests are skipped, so a
//! plain `cargo test` stays offline.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const ADMIN_PW: &str = "ldapm-admin-secret\n";

fn enabled() -> bool {
    let on = std::env::var_os("LDAPM_TESTDIR").is_some();
    if !on {
        eprintln!("skipped: set LDAPM_TESTDIR=1 with testdir/run.sh up");
    }
    on
}

fn certs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdir/certs")
}

/// An isolated config dir with the standard test profiles.
struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let env = Env { dir: tempfile::tempdir().unwrap() };
        env.add("test", &["--host", "localhost", "--port", "6360"], "ca.pem");
        env.add("starttls", &["--host", "localhost", "--port", "3890", "--starttls"], "ca.pem");
        env.add("wrong-ca", &["--host", "localhost", "--port", "6360"], "other-ca.pem");
        env.ldapm().args(["profile", "edit", "test", "--default"]).assert().success();
        env
    }

    fn add(&self, name: &str, conn: &[&str], ca: &str) {
        let ca = certs().join(ca);
        self.ldapm()
            .args(["profile", "add", name])
            .args(conn)
            .arg("--ca")
            .arg(ca)
            .args(["--bind-dn", "cn=ldapm-admin,dc=example,dc=org", "--base-dn", "dc=example,dc=org"])
            .assert()
            .success();
    }

    fn ldapm(&self) -> Command {
        let mut cmd = Command::cargo_bin("ldapm").unwrap();
        cmd.env("LDAPM_CONFIG_DIR", self.dir.path()).env_remove("LDAPM_PROFILE");
        cmd
    }

    /// Run as the admin with the password on stdin; return stdout.
    fn run_ok(&self, args: &[&str]) -> String {
        let out = self.ldapm().arg("--password-stdin").args(args).write_stdin(ADMIN_PW).output().unwrap();
        assert!(out.status.success(), "{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    /// Run expecting failure; return (exit code, stderr).
    fn run_err(&self, args: &[&str], stdin: &str) -> (i32, String) {
        let out = self.ldapm().arg("--password-stdin").args(args).write_stdin(stdin).output().unwrap();
        assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
        (out.status.code().unwrap(), String::from_utf8(out.stderr).unwrap())
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.run_ok(&a)).unwrap()
    }
}

#[test]
fn whoami_over_ldaps_and_starttls() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    assert_eq!(env.run_ok(&["whoami"]).trim(), "dn:cn=ldapm-admin,dc=example,dc=org");
    let j = env.json(&["-p", "starttls", "whoami"]);
    assert_eq!(j["tls"], "starttls");
    assert_eq!(j["authz_id"], "dn:cn=ldapm-admin,dc=example,dc=org");
}

#[test]
fn pinned_ca_rejects_other_issuers() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let (code, err) = env.run_err(&["-p", "wrong-ca", "whoami"], ADMIN_PW);
    assert_eq!(code, 2);
    assert!(err.contains("UnknownIssuer"), "{err}");
}

#[test]
fn bad_password_is_a_directory_error() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let (code, err) = env.run_err(&["whoami"], "not-the-password\n");
    assert_eq!(code, 2);
    assert!(err.contains("49 (invalidCredentials)"), "{err}");
}

#[test]
fn profile_test_reports_each_step() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let out = env.run_ok(&["profile", "test"]);
    for needle in [
        "TLS (ldaps) verified",
        "Bound as dn:cn=ldapm-admin",
        "people base",
        "groups base",
        "7 groups found",
        "36 users found",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
    }
}

#[test]
fn profile_test_suggests_an_existing_base() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    env.ldapm()
        .args(["profile", "edit", "test", "--people-base", "ou=users,dc=example,dc=org"])
        .assert()
        .success();
    let out =
        env.ldapm().args(["--password-stdin", "profile", "test"]).write_stdin(ADMIN_PW).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hint: ou=people,dc=example,dc=org exists"), "{stdout}");
}

#[test]
fn tree_listing_pages_past_the_size_limit() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    // olcSizeLimit is 25; there are 36 people, so this only works with paging.
    let j = env.json(&["entry", "ls", "ou=people,dc=example,dc=org"]);
    assert_eq!(j["nodes"].as_array().unwrap().len(), 36);
    assert_eq!(j["truncated"], false);
    let top = env.json(&["entry", "ls"]);
    let rdns: Vec<&str> =
        top["nodes"].as_array().unwrap().iter().map(|n| n["rdn"].as_str().unwrap()).collect();
    assert_eq!(rdns, ["cn=ldapm-admin", "ou=groups", "ou=people", "ou=policies"]);
}

#[test]
fn entry_show_hides_passwords_and_summarises_binary() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let out = env.run_ok(&["entry", "show", "uid=jdoe,ou=people,dc=example,dc=org"]);
    assert!(out.contains("userPassword: <hidden>"), "{out}");
    assert!(out.contains("jpegPhoto: <binary, 26 bytes>"), "{out}");
    assert!(!out.contains("{SSHA}"), "{out}");
    let (code, err) = env.run_err(&["entry", "show", "uid=nobody,dc=example,dc=org"], ADMIN_PW);
    assert_eq!(code, 2);
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn search_escapes_filter_input() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let hits = env.json(&["entry", "search", "doe"]);
    assert_eq!(hits.as_array().unwrap().len(), 1);
    // Unescaped, this would match every entry with a uid.
    let hits = env.json(&["entry", "search", "x*)(uid=*", "--by", "uid"]);
    assert_eq!(hits.as_array().unwrap().len(), 0);
}

#[test]
fn user_show_status_groups_and_policy() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let u = env.json(&["user", "show", "jdoe"]);
    assert_eq!(u["status"]["state"], "active");
    let groups: Vec<(&str, bool)> = u["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["cn"].as_str().unwrap(), g["primary"].as_bool().unwrap()))
        .collect();
    assert_eq!(groups, [("staff", true), ("devs", false), ("project-x", false), ("vpn", false)]);

    assert_eq!(env.json(&["user", "show", "mlocked"])["status"]["state"], "disabled");
    assert_eq!(
        env.json(&["user", "show", "svc-backup"])["policy"],
        "cn=service,ou=policies,dc=example,dc=org"
    );
    assert_eq!(env.json(&["user", "show", "ietxeberria"])["cn"], "Iñaki Etxeberria");
    let (code, _) = env.run_err(&["user", "show", "nobody"], ADMIN_PW);
    assert_eq!(code, 2);
}

#[test]
fn group_show_flags_dangling_members() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let g = env.json(&["group", "show", "devs"]);
    let members: Vec<(&str, bool)> = g["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["value"].as_str().unwrap(), m["exists"].as_bool().unwrap()))
        .collect();
    assert_eq!(members, [("asmith", true), ("ghost", false), ("jdoe", true)]);
    assert!(g["members"].as_array().unwrap().iter().all(|m| m["attr"] == "memberUid"));
    let list = env.json(&["group", "list"]);
    let counts: Vec<(&str, u64)> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["cn"].as_str().unwrap(), g["member_count"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        counts,
        [
            ("admins", 1),
            ("auditors", 2),
            ("devs", 3),
            ("empty", 0),
            ("project-x", 4),
            ("staff", 0),
            ("vpn", 2)
        ]
    );
}

#[test]
fn dn_valued_groups_and_non_posix_users() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let g = env.json(&["group", "show", "project-x"]);
    let members: Vec<(&str, &str, bool)> = g["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["value"].as_str().unwrap(), m["attr"].as_str().unwrap(), m["exists"].as_bool().unwrap()))
        .collect();
    assert_eq!(
        members,
        [
            ("cn=devs,ou=groups,dc=example,dc=org", "member", true),
            ("uid=contractor,ou=people,dc=example,dc=org", "member", true),
            ("uid=gone,ou=people,dc=example,dc=org", "member", false),
            ("uid=jdoe,ou=people,dc=example,dc=org", "member", true),
        ]
    );
    let out = env.run_ok(&["group", "show", "project-x"]);
    assert!(out.contains("4 (1 dangling)") && out.contains("! no such entry"), "{out}");

    let g = env.json(&["group", "show", "auditors"]);
    assert!(g["members"].as_array().unwrap().iter().all(|m| m["exists"] == true), "{g}");

    // A plain inetOrgPerson is a user, and DN memberships are found.
    let u = env.json(&["user", "show", "contractor"]);
    assert_eq!(u["uid_number"], serde_json::Value::Null);
    let groups: Vec<&str> =
        u["groups"].as_array().unwrap().iter().map(|g| g["cn"].as_str().unwrap()).collect();
    // Not auditors: its value carries #'0101'B, and RFC 4517 uniqueMemberMatch
    // does not match a stored identifier against an assertion without one.
    assert_eq!(groups, ["project-x"]);
    let asmith = env.json(&["user", "show", "asmith"]);
    assert!(asmith["groups"].as_array().unwrap().iter().any(|g| g["cn"] == "auditors"), "{asmith}");
    let jdoe = env.json(&["user", "show", "jdoe"]);
    let groups: Vec<&str> =
        jdoe["groups"].as_array().unwrap().iter().map(|g| g["cn"].as_str().unwrap()).collect();
    assert_eq!(groups, ["staff", "devs", "project-x", "vpn"]);
    assert_eq!(env.json(&["user", "search", "contractor"]).as_array().unwrap().len(), 1);

    // A narrower filter is honoured.
    env.ldapm()
        .args(["profile", "edit", "test", "--user-filter", "(objectClass=posixAccount)"])
        .assert()
        .success();
    let (code, _) = env.run_err(&["user", "show", "contractor"], ADMIN_PW);
    assert_eq!(code, 2);
}

#[test]
fn json_errors_are_machine_readable() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let (code, err) = env.run_err(&["--json", "user", "show", "nobody"], ADMIN_PW);
    assert_eq!(code, 2);
    let j: serde_json::Value = serde_json::from_str(err.trim()).unwrap();
    assert_eq!(j["error"]["code"], "not_found");
    assert_eq!(j["error"]["exit_code"], 2);
    let (_, err) = env.run_err(&["--json", "whoami"], "wrong\n");
    let j: serde_json::Value = serde_json::from_str(err.trim()).unwrap();
    assert_eq!(j["error"]["ldap_code"], 49);
}

#[test]
fn user_search_lists_all_users_with_paging() {
    if !enabled() {
        return;
    }
    let env = Env::new();
    let hits = env.json(&["user", "search", "user"]);
    assert_eq!(hits.as_array().unwrap().len(), 30);
}

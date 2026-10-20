//! CLI behaviour that needs no directory.

use assert_cmd::Command;

fn ldapm(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ldapm").unwrap();
    cmd.env("LDAPM_CONFIG_DIR", dir).env_remove("LDAPM_PROFILE");
    cmd
}

#[test]
fn usage_errors_exit_1_and_help_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    ldapm(dir.path()).arg("frobnicate").assert().code(1);
    ldapm(dir.path()).arg("--help").assert().code(0);
}

#[test]
fn no_profiles_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = ldapm(dir.path()).arg("whoami").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no profiles yet"));
}

#[test]
fn profile_add_rejects_non_pem_ca_and_bad_names() {
    let dir = tempfile::tempdir().unwrap();
    let not_pem = dir.path().join("x.txt");
    std::fs::write(&not_pem, "hello").unwrap();
    let base = ["--host", "h", "--bind-dn", "cn=a", "--base-dn", "dc=x"];
    ldapm(dir.path()).args(["profile", "add", "p"]).args(base).arg("--ca").arg(&not_pem).assert().code(1);
    ldapm(dir.path())
        .args(["profile", "add", "../evil"])
        .args(base)
        .arg("--ca")
        .arg(&not_pem)
        .assert()
        .code(1);
    assert!(!dir.path().join("profiles.toml").exists());
}

#[test]
fn ssh_target_cannot_inject_options() {
    let dir = tempfile::tempdir().unwrap();
    let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdir/certs/ca.pem");
    if !ca.exists() {
        eprintln!("skipped: run testdir/make-certs.sh");
        return;
    }
    let add = |ssh: &str| {
        ldapm(dir.path())
            .args(["profile", "add", "p", "--host", "h", "--bind-dn", "cn=a", "--base-dn", "dc=x"])
            .arg("--ca")
            .arg(&ca)
            .arg(format!("--ssh={ssh}"))
            .output()
            .unwrap()
    };
    // Rejected when saving the profile...
    let out = add("-oProxyCommand=touch /tmp/pwned");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid ssh target"));

    // ...and again before spawning ssh if the file was edited by hand.
    assert!(add("admin@bastion").status.success());
    let path = dir.path().join("profiles.toml");
    let text = std::fs::read_to_string(&path).unwrap().replace("admin@bastion", "-oProxyCommand=x");
    std::fs::write(&path, text).unwrap();
    let out = ldapm(dir.path()).args(["--password-stdin", "whoami"]).write_stdin("pw\n").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid ssh target"));
}

#[test]
fn invalid_filters_are_rejected_before_saving() {
    let dir = tempfile::tempdir().unwrap();
    let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdir/certs/ca.pem");
    if !ca.exists() {
        eprintln!("skipped: run testdir/make-certs.sh");
        return;
    }
    let out = ldapm(dir.path())
        .args(["profile", "add", "p", "--host", "h", "--bind-dn", "cn=a", "--base-dn", "dc=x"])
        .arg("--ca")
        .arg(&ca)
        .args(["--user-filter", "objectClass=person"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid user filter"));
    assert!(!dir.path().join("profiles.toml").exists());
}

#[test]
fn json_errors_go_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let out = ldapm(dir.path()).args(["--json", "whoami"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let j: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(j["error"]["code"], "config");
}

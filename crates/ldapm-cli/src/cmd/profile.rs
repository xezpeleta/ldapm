use ldapm_core::conventions::ConventionsConfig;
use ldapm_core::profiles::{Profile, ProfileStore, Scheme, SshConfig};
use ldapm_core::secret;
use ldapm_core::session::Session;
use ldapm_core::{Error, Result};
use serde::Serialize;

use crate::cli::{ConventionArgs, ProfileCmd, SshArgs};
use crate::ctx::{Ctx, prompt_password};
use crate::output;

pub async fn run(ctx: &Ctx, cmd: ProfileCmd) -> Result<()> {
    // Profile commands change the local config file, so they need a mutable store.
    let mut store = ProfileStore::load(ctx.store.dir())?;
    match cmd {
        ProfileCmd::List => list(ctx, &store),
        ProfileCmd::Show { name } => show(ctx, name.as_deref()),
        ProfileCmd::Add { name, conn, default } => {
            if store.contains(&name) {
                return Err(Error::Validation(format!(
                    "profile \"{name}\" already exists; use `profile edit`"
                )));
            }
            ldapm_core::profiles::validate_name(&name)?;
            let mut conventions = ConventionsConfig::default();
            apply_conventions(&mut conventions, conn.conventions);
            conventions.validate()?;
            let ca = store.import_ca(&name, &conn.ca)?;
            let profile = Profile {
                host: conn.host,
                port: conn.port,
                scheme: if conn.starttls { Scheme::Starttls } else { Scheme::Ldaps },
                ca,
                bind_dn: conn.bind_dn,
                base_dn: conn.base_dn,
                remember_password: false,
                ssh: ssh_config(conn.ssh, None),
                conventions,
            };
            let url = profile.url();
            store.insert(&name, profile)?;
            if default {
                store.set_default(&name)?;
            }
            store.save()?;
            eprintln!("Saved profile \"{name}\" ({url}, CA pinned)");
            Ok(())
        }
        ProfileCmd::Edit { name, conn, default, remember_password, forget_password } => {
            let new_ca = match &conn.ca {
                Some(path) => Some(store.import_ca(&name, path)?),
                None => None,
            };
            let p = store.get_mut(&name)?;
            if let Some(v) = conn.host {
                p.host = v;
            }
            if let Some(v) = conn.port {
                p.port = Some(v);
            }
            if let Some(v) = conn.starttls {
                p.scheme = if v { Scheme::Starttls } else { Scheme::Ldaps };
            }
            if let Some(v) = new_ca {
                p.ca = v;
            }
            if let Some(v) = conn.bind_dn {
                p.bind_dn = v;
            }
            if let Some(v) = conn.base_dn {
                p.base_dn = v;
            }
            if conn.no_ssh {
                p.ssh = None;
            } else if conn.ssh.ssh.is_some() {
                p.ssh = ssh_config(conn.ssh, p.ssh.take());
            }
            apply_conventions(&mut p.conventions, conn.conventions);
            let profile = p.clone();

            if remember_password {
                let password = if ctx.password_stdin {
                    ctx.bind_password(&name, &Profile { remember_password: false, ..profile.clone() }).await?
                } else {
                    prompt_password(&profile.bind_dn)?
                };
                // Only store a password that actually binds.
                let session = Session::connect(&profile, &store.ca_path(&profile), &password).await?;
                session.close().await;
                let n = name.clone();
                blocking(move || secret::store(&n, &password)).await?;
                store.get_mut(&name)?.remember_password = true;
                eprintln!("Bind password verified and stored in the Secret Service");
            }
            if forget_password {
                let n = name.clone();
                blocking(move || secret::forget(&n)).await?;
                store.get_mut(&name)?.remember_password = false;
                eprintln!("Stored bind password deleted");
            }
            if default {
                store.set_default(&name)?;
            }
            store.save()?;
            eprintln!("Saved profile \"{name}\"");
            Ok(())
        }
        ProfileCmd::Rm { name } => {
            let removed = store.remove(&name)?;
            store.save()?;
            if removed.remember_password {
                let n = name.clone();
                if let Err(e) = blocking(move || secret::forget(&n)).await {
                    eprintln!("warning: profile removed but the stored password was not: {e}");
                }
            }
            eprintln!("Removed profile \"{name}\"");
            Ok(())
        }
        ProfileCmd::Test { name } => test(ctx, name.as_deref()).await,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| Error::Keyring(format!("keyring task failed: {e}")))?
}

fn ssh_config(args: SshArgs, previous: Option<SshConfig>) -> Option<SshConfig> {
    let target = args.ssh?;
    Some(SshConfig {
        target,
        port: args.ssh_port.or(previous.as_ref().map(|p| p.port)).unwrap_or(22),
        identity: args.ssh_identity.or(previous.as_ref().and_then(|p| p.identity.clone())),
        known_hosts: args.ssh_known_hosts.or(previous.and_then(|p| p.known_hosts)),
    })
}

fn apply_conventions(c: &mut ConventionsConfig, args: ConventionArgs) {
    if args.people_base.is_some() {
        c.people_base = args.people_base;
    }
    if args.groups_base.is_some() {
        c.groups_base = args.groups_base;
    }
    if args.user_filter.is_some() {
        c.user_filter = args.user_filter;
    }
    if args.group_filter.is_some() {
        c.group_filter = args.group_filter;
    }
    if args.mail_domain.is_some() {
        c.mail_domain = args.mail_domain;
    }
}

#[derive(Serialize)]
struct Row<'a> {
    name: &'a str,
    default: bool,
    url: String,
    tunnel: Option<&'a str>,
    remember_password: bool,
}

fn list(ctx: &Ctx, store: &ProfileStore) -> Result<()> {
    let rows: Vec<Row> = store
        .names()
        .map(|(name, p)| Row {
            name,
            default: store.default_name() == Some(name),
            url: p.url(),
            tunnel: p.ssh.as_ref().map(|s| s.target.as_str()),
            remember_password: p.remember_password,
        })
        .collect();
    if ctx.json {
        output::json(&rows);
        return Ok(());
    }
    if rows.is_empty() {
        eprintln!("No profiles yet. Create one with `ldapm profile add`.");
        return Ok(());
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                format!("{} {}", if r.default { "*" } else { " " }, r.name),
                r.url.clone(),
                r.tunnel.unwrap_or("-").to_string(),
                if r.remember_password { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    output::table(&["  NAME", "URL", "TUNNEL", "KEYRING"], &table);
    Ok(())
}

fn show(ctx: &Ctx, name: Option<&str>) -> Result<()> {
    let (name, p) = ctx.profile(name)?;
    let conv = p.conventions();
    if ctx.json {
        #[derive(Serialize)]
        struct Show<'a> {
            name: &'a str,
            url: String,
            ca: String,
            #[serde(flatten)]
            profile: &'a Profile,
            resolved_conventions: &'a ldapm_core::conventions::Conventions,
        }
        output::json(&Show {
            name: &name,
            url: p.url(),
            ca: ctx.store.ca_path(&p).display().to_string(),
            profile: &p,
            resolved_conventions: &conv,
        });
        return Ok(());
    }
    output::fields(&[
        ("profile", name.clone()),
        ("url", p.url()),
        ("ca", ctx.store.ca_path(&p).display().to_string()),
        ("bind dn", p.bind_dn.clone()),
        ("base dn", p.base_dn.clone()),
        ("tunnel", p.ssh.as_ref().map_or("-".into(), |s| format!("{} (port {})", s.target, s.port))),
        ("keyring", if p.remember_password { "yes" } else { "no" }.into()),
        ("people", conv.people_base.clone()),
        ("groups", conv.groups_base.clone()),
        ("user filter", conv.user_filter.clone()),
        ("group filter", conv.group_filter.clone()),
        ("mail domain", output::opt(&conv.mail_domain)),
    ]);
    Ok(())
}

/// Common people/group containers, checked when the configured base is missing:
/// OpenLDAP and 389 DS conventions, FreeIPA, and the Samba/AD-style `cn=Users`.
const PEOPLE_CANDIDATES: &[&str] = &["ou=people", "ou=users", "cn=users,cn=accounts", "cn=users"];
const GROUP_CANDIDATES: &[&str] = &["ou=groups", "ou=group", "cn=groups,cn=accounts", "cn=groups"];

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Step-by-step diagnosis so a failure is attributed to the right layer.
async fn test(ctx: &Ctx, name: Option<&str>) -> Result<()> {
    let (name, p) = ctx.profile(name)?;
    let ca_path = ctx.store.ca_path(&p);
    let ca = match ldapm_core::tls::load_ca(&ca_path) {
        Ok(certs) => certs,
        Err(e) => {
            output::fail(e.to_string());
            return Err(e);
        }
    };
    output::ok(format!("CA file {} ({} certificate{})", ca_path.display(), ca.len(), plural(ca.len())));

    let mut session = match Session::open(&p, &ca_path).await {
        Ok(s) => s,
        Err(e) => {
            output::fail(e.to_string());
            return Err(e);
        }
    };
    let info = session.info().clone();
    if let Some(t) = &info.tunnel {
        output::ok(format!(
            "SSH tunnel up (127.0.0.1:{} → {}:{} via {})",
            t.local_port,
            p.host,
            p.port(),
            t.via
        ));
    }
    output::ok(format!("TLS ({}) verified against the pinned CA, hostname {}", info.tls, p.host));

    let password = ctx.bind_password(&name, &p).await?;
    if let Err(e) = session.bind(&p.bind_dn, &password).await {
        output::fail(format!("bind as {}: {e}", p.bind_dn));
        return Err(e);
    }
    let authz = session.whoami().await?;
    output::ok(format!("Bound as {authz}"));

    let conv = session.conventions().clone();
    let mut failed = None;
    for (label, dn, flag, candidates) in [
        ("base DN", &conv.base_dn, "--base-dn", &[][..]),
        ("people base", &conv.people_base, "--people-base", PEOPLE_CANDIDATES),
        ("groups base", &conv.groups_base, "--groups-base", GROUP_CANDIDATES),
    ] {
        match session.get_entry(dn, false).await {
            Ok(_) => output::ok(format!("{label} {dn} readable")),
            Err(e) => {
                output::fail(format!("{label} {dn}: {e}"));
                for rdn in candidates {
                    let dn = format!("{rdn},{}", conv.base_dn);
                    if session.get_entry(&dn, false).await.is_ok() {
                        println!("  hint: {dn} exists; try `ldapm profile edit {name} {flag} '{dn}'`");
                        break;
                    }
                }
                failed.get_or_insert(e);
            }
        }
    }
    if failed.is_none() {
        // Empty results usually mean the directory uses other object classes.
        match session.list_groups().await {
            Ok(g) if g.is_empty() => output::warn(format!(
                "no groups match the group filter {}; set one with `--group-filter`",
                conv.group_filter
            )),
            Ok(g) => output::ok(format!("{} group{} found", g.len(), plural(g.len()))),
            Err(e) => output::warn(format!("counting groups: {e}")),
        }
        match session.count_users().await {
            Ok(0) => output::warn(format!(
                "no users match the user filter {}; set one with `--user-filter`",
                conv.user_filter
            )),
            Ok(n) => output::ok(format!("{n} user{} found", plural(n))),
            Err(e) => output::warn(format!("counting users: {e}")),
        }
    }
    session.close().await;
    match failed {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

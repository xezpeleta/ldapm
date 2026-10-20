//! A bound connection to one profile's directory.
//!
//! `ldap3::Ldap` handles are cheap clones multiplexed over one connection,
//! so a `Session` owns one handle plus the connection driver task and hands
//! out clones per operation. No mutex is held across awaits.

mod reads;

pub use reads::*;

use std::time::Duration;

use ldap3::exop::WhoAmI;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, StdStream};
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::conventions::Conventions;
use crate::error::map_ldap;
use crate::profiles::{Profile, Scheme};
use crate::secret::Secret;
use crate::tunnel::Tunnel;
use crate::{Error, Result, tls};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OP_TIMEOUT: Duration = Duration::from_secs(30);

/// What was established, for display.
#[derive(Debug, Clone, Serialize)]
pub struct ConnInfo {
    pub url: String,
    pub tls: &'static str,
    /// `user@host` and local port, when tunnelled.
    pub tunnel: Option<TunnelInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelInfo {
    pub via: String,
    pub local_port: u16,
}

pub struct Session {
    ldap: Ldap,
    driver: JoinHandle<()>,
    // Kept alive for the session's lifetime; dropping it kills ssh.
    _tunnel: Option<Tunnel>,
    info: ConnInfo,
    conventions: Conventions,
    bound_dn: Option<String>,
}

impl Session {
    /// Open the tunnel (if configured), connect and complete TLS. Not bound yet.
    pub async fn open(profile: &Profile, ca_path: &std::path::Path) -> Result<Session> {
        let config = tls::client_config(ca_path)?;
        let url = profile.url();

        let tunnel = match &profile.ssh {
            Some(ssh) => Some(Tunnel::open(ssh, &profile.host, profile.port()).await?),
            None => None,
        };

        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(CONNECT_TIMEOUT)
            .set_starttls(profile.scheme == Scheme::Starttls)
            .set_config(config);
        if let Some(t) = &tunnel {
            // The URL still names the real host, so TLS verifies against it.
            settings = settings.set_std_stream(StdStream::Tcp(t.connect()?));
        }

        let (conn, ldap) =
            LdapConnAsync::with_settings(settings, &url).await.map_err(|e| connect_error(&url, e))?;
        let driver = tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::warn!(target: "ldapm::session", "connection closed: {e}");
            }
        });

        let info = ConnInfo {
            url,
            tls: match profile.scheme {
                Scheme::Ldaps => "ldaps",
                Scheme::Starttls => "starttls",
            },
            tunnel: tunnel
                .as_ref()
                .map(|t| TunnelInfo { via: t.via().to_string(), local_port: t.local_port() }),
        };
        Ok(Session {
            ldap,
            driver,
            _tunnel: tunnel,
            info,
            conventions: profile.conventions(),
            bound_dn: None,
        })
    }

    /// Open and bind in one step.
    pub async fn connect(profile: &Profile, ca_path: &std::path::Path, password: &Secret) -> Result<Session> {
        let mut session = Session::open(profile, ca_path).await?;
        session.bind(&profile.bind_dn, password).await?;
        Ok(session)
    }

    pub async fn bind(&mut self, dn: &str, password: &Secret) -> Result<()> {
        if password.expose().is_empty() {
            // An empty password is an unauthenticated bind (RFC 4513 §5.1.2).
            return Err(Error::Validation("empty bind password".into()));
        }
        let res = self.ldap().simple_bind(dn, password.expose()).await.map_err(map_ldap)?;
        if res.rc != 0 {
            return Err(Error::from_result(&res));
        }
        self.bound_dn = Some(dn.to_string());
        Ok(())
    }

    /// Ask the server which identity it authorized (RFC 4532).
    pub async fn whoami(&self) -> Result<String> {
        let (exop, _) = self.ldap().extended(WhoAmI).await.map_err(map_ldap)?.success().map_err(map_ldap)?;
        // Parse by hand: ldap3's parser panics on an absent or non-UTF-8 value.
        let authzid = exop.val.map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
        Ok(authzid)
    }

    pub fn info(&self) -> &ConnInfo {
        &self.info
    }

    pub fn conventions(&self) -> &Conventions {
        &self.conventions
    }

    pub fn bound_dn(&self) -> Option<&str> {
        self.bound_dn.as_deref()
    }

    /// True once the connection driver has stopped.
    pub fn is_closed(&self) -> bool {
        self.driver.is_finished()
    }

    pub(crate) fn ldap(&self) -> Ldap {
        let mut ldap = self.ldap.clone();
        ldap.with_timeout(OP_TIMEOUT);
        ldap
    }

    pub async fn close(self) {
        let mut ldap = self.ldap.clone();
        let _ = ldap.unbind().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.driver).await;
    }
}

fn connect_error(url: &str, e: ldap3::LdapError) -> Error {
    let reason = error_chain(&e);
    if reason.contains("certificate") || reason.contains("InvalidCertificate") || reason.contains("tls") {
        Error::Tls(format!("{url}: {reason}"))
    } else {
        Error::Connect { url: url.to_string(), reason }
    }
}

/// `Display` of an error and all its sources, joined with ": ".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        src = s.source();
    }
    out
}

//! SSH local port forward by spawning the system `ssh` binary.
//!
//! The child runs with `BatchMode=yes` (no hidden password prompts; keys or
//! an agent must be set up), `StrictHostKeyChecking=yes` (the jump host's
//! key must already be known, optionally from a per-profile known_hosts
//! file) and `ExitOnForwardFailure=yes`, and is killed when the `Tunnel` is
//! dropped.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use crate::profiles::SshConfig;
use crate::{Error, Result};

const READY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct Tunnel {
    child: Child,
    local_port: u16,
    via: String,
}

impl Tunnel {
    /// Forward `127.0.0.1:<free port>` to `remote_host:remote_port` via `ssh`.
    pub async fn open(ssh: &SshConfig, remote_host: &str, remote_port: u16) -> Result<Tunnel> {
        validate_ssh_arg("ssh target", &ssh.target)?;
        validate_ssh_arg("directory host", remote_host)?;
        let local_port = free_port()?;
        let forward = format!(
            "127.0.0.1:{local_port}:{}:{remote_port}",
            if remote_host.contains(':') { format!("[{remote_host}]") } else { remote_host.to_string() }
        );

        let mut cmd = Command::new("ssh");
        cmd.args(["-N", "-o", "ExitOnForwardFailure=yes", "-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "ServerAliveInterval=30"])
            .args(["-p", &ssh.port.to_string()])
            .args(["-L", &forward]);
        if let Some(identity) = &ssh.identity {
            cmd.arg("-i").arg(expand_home(identity)).args(["-o", "IdentitiesOnly=yes"]);
        }
        if let Some(known_hosts) = &ssh.known_hosts {
            let mut opt = std::ffi::OsString::from("UserKnownHostsFile=");
            opt.push(expand_home(known_hosts));
            cmd.arg("-o").arg(opt);
        }
        cmd.arg("--").arg(&ssh.target);
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);

        tracing::debug!(target: "ldapm::tunnel", ?forward, target_host = %ssh.target, "spawning ssh");
        let child = cmd.spawn().map_err(|e| Error::Tunnel(format!("cannot run ssh: {e}")))?;
        let mut tunnel = Tunnel { child, local_port, via: ssh.target.clone() };
        tunnel.wait_ready().await?;
        Ok(tunnel)
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.local_port));
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| Error::Tunnel(e.to_string()))? {
                let mut stderr = String::new();
                if let Some(mut err) = self.child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr).await;
                }
                let detail = stderr.trim();
                return Err(Error::Tunnel(if detail.is_empty() {
                    format!("ssh exited with {status}")
                } else {
                    format!("ssh exited with {status}: {detail}")
                }));
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if start.elapsed() > READY_TIMEOUT {
                return Err(Error::Tunnel(format!(
                    "forward on 127.0.0.1:{} not ready after {}s",
                    self.local_port,
                    READY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn via(&self) -> &str {
        &self.via
    }

    /// A fresh TCP connection to the local end of the forward.
    pub fn connect(&self) -> Result<TcpStream> {
        TcpStream::connect((Ipv4Addr::LOCALHOST, self.local_port))
            .map_err(|e| Error::Tunnel(format!("connecting to forwarded port: {e}")))
    }
}

/// Bind port 0 to let the OS choose, then release it for ssh to use.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| Error::Tunnel(format!("cannot pick a local port: {e}")))?;
    let port = listener.local_addr().map_err(|e| Error::Tunnel(e.to_string()))?.port();
    Ok(port)
}

/// Reject values ssh could parse as options or that contain whitespace.
pub(crate) fn validate_ssh_arg(what: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::Validation(format!("invalid {what}: {value:?}")));
    }
    Ok(())
}

fn expand_home(path: &std::path::Path) -> PathBuf {
    match (path.strip_prefix("~"), dirs::home_dir()) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_option_like_args() {
        assert!(validate_ssh_arg("t", "admin@bastion").is_ok());
        assert!(validate_ssh_arg("t", "-oProxyCommand=evil").is_err());
        assert!(validate_ssh_arg("t", "a b").is_err());
        assert!(validate_ssh_arg("t", "").is_err());
    }
}

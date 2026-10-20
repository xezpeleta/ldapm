use std::io::{BufRead, IsTerminal};

use zeroize::Zeroize;

use ldapm_core::profiles::{Profile, ProfileStore};
use ldapm_core::secret::{self, Secret};
use ldapm_core::session::Session;
use ldapm_core::{Error, Result};

use crate::cli::Cli;

/// Per-invocation state shared by all handlers.
pub struct Ctx {
    pub store: ProfileStore,
    pub profile: Option<String>,
    pub json: bool,
    pub password_stdin: bool,
}

impl Ctx {
    pub fn new(cli: &Cli) -> Result<Ctx> {
        Ok(Ctx {
            store: ProfileStore::load_default()?,
            profile: cli.profile.clone(),
            json: cli.json,
            password_stdin: cli.password_stdin,
        })
    }

    /// The selected profile (explicit name wins over --profile).
    pub fn profile(&self, explicit: Option<&str>) -> Result<(String, Profile)> {
        let (name, p) = self.store.resolve(explicit.or(self.profile.as_deref()))?;
        Ok((name, p.clone()))
    }

    /// Connect and bind with the selected profile.
    pub async fn session(&self) -> Result<Session> {
        let (name, profile) = self.profile(None)?;
        let password = self.bind_password(&name, &profile).await?;
        Session::connect(&profile, &self.store.ca_path(&profile), &password).await
    }

    /// Keyring (if opted in), else stdin (if asked), else a terminal prompt.
    pub async fn bind_password(&self, name: &str, profile: &Profile) -> Result<Secret> {
        if self.password_stdin {
            return read_stdin_password();
        }
        if profile.remember_password {
            let n = name.to_string();
            match tokio::task::spawn_blocking(move || secret::load(&n)).await {
                Ok(Ok(Some(pw))) => return Ok(pw),
                Ok(Ok(None)) => eprintln!("warning: no stored password for \"{name}\"; asking instead"),
                Ok(Err(e)) => eprintln!("warning: {e}; asking instead"),
                Err(e) => eprintln!("warning: keyring task failed: {e}; asking instead"),
            }
        }
        prompt_password(&profile.bind_dn)
    }
}

pub fn prompt_password(bind_dn: &str) -> Result<Secret> {
    if !std::io::stdin().is_terminal() && !std::io::stderr().is_terminal() {
        return Err(Error::Validation(
            "no terminal to ask for the bind password; use --password-stdin".into(),
        ));
    }
    rpassword::prompt_password(format!("Bind password for {bind_dn}: ")).map(Secret::new).map_err(|e| {
        Error::Validation(format!("cannot read password from the terminal: {e}; use --password-stdin"))
    })
}

fn read_stdin_password() -> Result<Secret> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::Validation(format!("reading password from stdin: {e}")))?;
    let pw = line.trim_end_matches(['\r', '\n']).to_string();
    // Wipe the buffer copy; `pw` is wiped when the Secret drops.
    line.zeroize();
    if pw.is_empty() {
        return Err(Error::Validation("empty password on stdin".into()));
    }
    Ok(Secret::new(pw))
}

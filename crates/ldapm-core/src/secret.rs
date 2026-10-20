//! Bind passwords: held in a zeroizing wrapper, optionally kept in the
//! Secret Service (GNOME Keyring / KWallet) when the user opts in.
//!
//! The store uses a blocking D-Bus API. Async callers must run these
//! functions through `tokio::task::spawn_blocking`.

use std::fmt;
use std::sync::Once;

use zeroize::Zeroizing;

use crate::{Error, Result};

const SERVICE: &str = "ldapm";

/// A secret string that is wiped on drop and never printed.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(Zeroizing::new(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

static INIT: Once = Once::new();

fn ensure_store() -> Result<()> {
    let mut err = None;
    INIT.call_once(|| match zbus_secret_service_keyring_store::Store::new() {
        Ok(store) => keyring_core::set_default_store(store),
        Err(e) => err = Some(e.to_string()),
    });
    match err {
        Some(e) => Err(Error::Keyring(format!("Secret Service unavailable: {e}"))),
        None => Ok(()),
    }
}

fn entry(profile: &str) -> Result<keyring_core::Entry> {
    ensure_store()?;
    keyring_core::Entry::new(SERVICE, profile).map_err(|e| Error::Keyring(e.to_string()))
}

/// Stored bind password for a profile, or `None` if there is none.
pub fn load(profile: &str) -> Result<Option<Secret>> {
    match entry(profile)?.get_password() {
        Ok(pw) => Ok(Some(Secret::new(pw))),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::Keyring(e.to_string())),
    }
}

pub fn store(profile: &str, password: &Secret) -> Result<()> {
    entry(profile)?.set_password(password.expose()).map_err(|e| Error::Keyring(e.to_string()))
}

/// Delete the stored password. Missing entries are not an error.
pub fn forget(profile: &str) -> Result<()> {
    match entry(profile)?.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Keyring(e.to_string())),
    }
}

//! Connection profiles stored in `<config>/ldapm/profiles.toml`.
//! Passwords are never written here (see `secret`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::conventions::{Conventions, ConventionsConfig};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// TLS from the first byte (port 636). The default.
    Ldaps,
    /// Plain LDAP upgraded with the StartTLS extended operation (port 389).
    Starttls,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Ldaps => 636,
            Scheme::Starttls => 389,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    /// `user@host` of the jump host.
    pub target: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
    /// Pinned host keys for the jump host. Default: ssh's own known_hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<PathBuf>,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default = "default_scheme")]
    pub scheme: Scheme,
    /// CA certificate, relative to the config dir unless absolute.
    pub ca: PathBuf,
    pub bind_dn: String,
    pub base_dn: String,
    #[serde(default)]
    pub remember_password: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshConfig>,
    #[serde(default, skip_serializing_if = "is_default_conventions")]
    pub conventions: ConventionsConfig,
}

fn default_scheme() -> Scheme {
    Scheme::Ldaps
}

fn is_default_conventions(c: &ConventionsConfig) -> bool {
    *c == ConventionsConfig::default()
}

impl Profile {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.scheme.default_port())
    }

    /// The URL ldap3 connects to. The host part is also the TLS server name,
    /// so it stays the real directory host even when tunnelled.
    pub fn url(&self) -> String {
        let proto = match self.scheme {
            Scheme::Ldaps => "ldaps",
            Scheme::Starttls => "ldap",
        };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        format!("{proto}://{host}:{}", self.port())
    }

    pub fn conventions(&self) -> Conventions {
        Conventions::resolve(&self.base_dn, &self.conventions)
    }

    /// Reject values that could be misread as options by `ssh`.
    pub fn validate(&self) -> Result<()> {
        if let Some(ssh) = &self.ssh {
            crate::tunnel::validate_ssh_arg("ssh target", &ssh.target)?;
            crate::tunnel::validate_ssh_arg("directory host", &self.host)?;
        }
        if self.host.is_empty() || self.host.chars().any(|c| c.is_whitespace() || c == '/') {
            return Err(Error::Validation(format!("invalid host {:?}", self.host)));
        }
        self.conventions.validate()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilesFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
}

/// File-backed profile collection. Load, mutate, then `save()`.
#[derive(Debug)]
pub struct ProfileStore {
    dir: PathBuf,
    file: ProfilesFile,
}

impl ProfileStore {
    /// `$LDAPM_CONFIG_DIR`, else `~/.config/ldapm`.
    pub fn default_dir() -> Result<PathBuf> {
        if let Some(dir) = std::env::var_os("LDAPM_CONFIG_DIR") {
            return Ok(PathBuf::from(dir));
        }
        dirs::config_dir()
            .map(|d| d.join("ldapm"))
            .ok_or_else(|| Error::Config("cannot determine the user config directory".into()))
    }

    pub fn load_default() -> Result<Self> {
        Self::load(&Self::default_dir()?)
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("profiles.toml");
        let file = match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProfilesFile::default(),
            Err(e) => return Err(Error::io(format!("reading {}", path.display()), e)),
        };
        Ok(ProfileStore { dir: dir.to_path_buf(), file })
    }

    pub fn save(&self) -> Result<()> {
        for (name, profile) in &self.file.profiles {
            profile.validate().map_err(|e| Error::Validation(format!("profile \"{name}\": {e}")))?;
        }
        fs::create_dir_all(&self.dir)
            .map_err(|e| Error::io(format!("creating {}", self.dir.display()), e))?;
        let path = self.dir.join("profiles.toml");
        let tmp = self.dir.join("profiles.toml.tmp");
        let text = toml::to_string_pretty(&self.file)
            .map_err(|e| Error::Config(format!("serialising profiles: {e}")))?;
        fs::write(&tmp, text).map_err(|e| Error::io(format!("writing {}", tmp.display()), e))?;
        fs::rename(&tmp, &path).map_err(|e| Error::io(format!("writing {}", path.display()), e))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn names(&self) -> impl Iterator<Item = (&str, &Profile)> {
        self.file.profiles.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn default_name(&self) -> Option<&str> {
        self.file.default.as_deref()
    }

    pub fn get(&self, name: &str) -> Result<&Profile> {
        self.file.profiles.get(name).ok_or_else(|| Error::ProfileNotFound(name.to_string()))
    }

    /// Pick a profile: explicit name, else the default, else the only one.
    pub fn resolve(&self, name: Option<&str>) -> Result<(String, &Profile)> {
        let name = match name.or(self.default_name()) {
            Some(n) => n.to_string(),
            None if self.file.profiles.len() == 1 => self.file.profiles.keys().next().unwrap().clone(),
            None if self.file.profiles.is_empty() => {
                return Err(Error::Config("no profiles yet; create one with `ldapm profile add`".into()));
            }
            None => {
                return Err(Error::Config(
                    "several profiles and no default; pass --profile or run `ldapm profile edit <name> --default`".into(),
                ));
            }
        };
        let profile = self.get(&name)?;
        Ok((name, profile))
    }

    /// Absolute path of a profile's CA file.
    pub fn ca_path(&self, profile: &Profile) -> PathBuf {
        if profile.ca.is_absolute() { profile.ca.clone() } else { self.dir.join(&profile.ca) }
    }

    /// Copy a CA file into `<config>/ca/<name>.pem` after checking it parses.
    /// Returns the relative path to store in the profile.
    pub fn import_ca(&self, name: &str, source: &Path) -> Result<PathBuf> {
        crate::tls::load_ca(source)?;
        let rel = PathBuf::from("ca").join(format!("{name}.pem"));
        let dest = self.dir.join(&rel);
        fs::create_dir_all(dest.parent().unwrap())
            .map_err(|e| Error::io(format!("creating {}", self.dir.display()), e))?;
        fs::copy(source, &dest).map_err(|e| Error::io(format!("copying CA to {}", dest.display()), e))?;
        Ok(rel)
    }

    pub fn insert(&mut self, name: &str, profile: Profile) -> Result<()> {
        validate_name(name)?;
        self.file.profiles.insert(name.to_string(), profile);
        Ok(())
    }

    pub fn get_mut(&mut self, name: &str) -> Result<&mut Profile> {
        self.file.profiles.get_mut(name).ok_or_else(|| Error::ProfileNotFound(name.to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.file.profiles.contains_key(name)
    }

    pub fn set_default(&mut self, name: &str) -> Result<()> {
        self.get(name)?;
        self.file.default = Some(name.to_string());
        Ok(())
    }

    /// Remove a profile and its imported CA file (if it lives in the config dir).
    pub fn remove(&mut self, name: &str) -> Result<Profile> {
        let profile =
            self.file.profiles.remove(name).ok_or_else(|| Error::ProfileNotFound(name.to_string()))?;
        if self.file.default.as_deref() == Some(name) {
            self.file.default = None;
        }
        if profile.ca.is_relative() {
            let _ = fs::remove_file(self.dir.join(&profile.ca));
        }
        Ok(profile)
    }
}

/// Profile names become file names and keyring keys: keep them boring.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !name.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "invalid profile name \"{name}\": use letters, digits, '-' and '_' (max 64)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profile {
        Profile {
            host: "ldap.example.org".into(),
            port: None,
            scheme: Scheme::Ldaps,
            ca: "ca/prod.pem".into(),
            bind_dn: "cn=ldapm-admin,dc=example,dc=org".into(),
            base_dn: "dc=example,dc=org".into(),
            remember_password: false,
            ssh: None,
            conventions: ConventionsConfig::default(),
        }
    }

    #[test]
    fn urls() {
        let mut p = sample();
        assert_eq!(p.url(), "ldaps://ldap.example.org:636");
        p.scheme = Scheme::Starttls;
        assert_eq!(p.url(), "ldap://ldap.example.org:389");
        p.port = Some(1389);
        assert_eq!(p.url(), "ldap://ldap.example.org:1389");
    }

    #[test]
    fn round_trip_and_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::load(dir.path()).unwrap();
        assert!(store.resolve(None).is_err());
        store.insert("prod", sample()).unwrap();
        // A single profile is picked without a default.
        assert_eq!(store.resolve(None).unwrap().0, "prod");
        store.insert("test", sample()).unwrap();
        assert!(store.resolve(None).is_err());
        store.set_default("test").unwrap();
        store.save().unwrap();

        let store = ProfileStore::load(dir.path()).unwrap();
        assert_eq!(store.resolve(None).unwrap().0, "test");
        assert_eq!(store.resolve(Some("prod")).unwrap().1, &sample());
    }

    #[test]
    fn names() {
        assert!(validate_name("prod-tunnel_2").is_ok());
        for bad in ["", "-x", "a/b", "a b", "../x"] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_documented_example() {
        let text = r#"
default = "prod"
[profiles.prod]
host = "ldap.example.org"
port = 636
scheme = "ldaps"
ca = "ca/prod.pem"
bind_dn = "cn=ldapm-admin,dc=example,dc=org"
base_dn = "dc=example,dc=org"
remember_password = false
[profiles.prod.ssh]
target = "admin@bastion.example.org"
port = 22
identity = "~/.ssh/id_ed25519"
[profiles.prod.conventions]
people_base = "ou=people,dc=example,dc=org"
groups_base = "ou=groups,dc=example,dc=org"
mail_domain = "example.org"
uid_number_range = [10000, 59999]
primary_gid = 20000
human_policy = "cn=default,ou=policies,dc=example,dc=org"
service_policy = "cn=service,ou=policies,dc=example,dc=org"
"#;
        let f: ProfilesFile = toml::from_str(text).unwrap();
        let p = &f.profiles["prod"];
        assert_eq!(p.ssh.as_ref().unwrap().target, "admin@bastion.example.org");
        assert_eq!(p.conventions.primary_gid, Some(20000));
    }
}

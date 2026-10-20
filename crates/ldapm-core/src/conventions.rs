//! Where users and groups live and how to recognise them. Values come from
//! the profile's `[conventions]` block; anything missing falls back to the
//! common layout (`ou=people` / `ou=groups` below the base DN) and the
//! standard schemas (RFC 2798 inetOrgPerson, RFC 2307 posix, RFC 4519 groups).

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The value ppolicy uses for an administrator-set permanent lock.
pub const PERMANENT_LOCK: &str = "000001010000Z";

/// `person` also matches its subclasses `organizationalPerson` and `inetOrgPerson`.
pub const DEFAULT_USER_FILTER: &str = "(|(objectClass=person)(objectClass=posixAccount))";

pub const DEFAULT_GROUP_FILTER: &str =
    "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))";

/// Optional overrides as written in `profiles.toml`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConventionsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub people_base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_base: Option<String>,
    /// LDAP filter selecting user entries below `people_base`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_filter: Option<String>,
    /// LDAP filter selecting group entries below `groups_base`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_number_range: Option<[u32; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_policy: Option<String>,
}

/// Fully resolved conventions for one profile.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Conventions {
    pub base_dn: String,
    pub people_base: String,
    pub groups_base: String,
    pub user_filter: String,
    pub group_filter: String,
    pub mail_domain: Option<String>,
    pub uid_number_range: [u32; 2],
    pub primary_gid: Option<u32>,
    pub human_policy: Option<String>,
    pub service_policy: Option<String>,
}

impl Conventions {
    pub fn resolve(base_dn: &str, cfg: &ConventionsConfig) -> Self {
        Conventions {
            base_dn: base_dn.to_string(),
            people_base: cfg.people_base.clone().unwrap_or_else(|| format!("ou=people,{base_dn}")),
            groups_base: cfg.groups_base.clone().unwrap_or_else(|| format!("ou=groups,{base_dn}")),
            user_filter: cfg.user_filter.clone().unwrap_or_else(|| DEFAULT_USER_FILTER.into()),
            group_filter: cfg.group_filter.clone().unwrap_or_else(|| DEFAULT_GROUP_FILTER.into()),
            mail_domain: cfg.mail_domain.clone().or_else(|| domain_from_dn(base_dn)),
            uid_number_range: cfg.uid_number_range.unwrap_or([10000, 59999]),
            primary_gid: cfg.primary_gid,
            human_policy: cfg.human_policy.clone(),
            service_policy: cfg.service_policy.clone(),
        }
    }
}

impl ConventionsConfig {
    /// Reject filters the server would refuse, before they are saved.
    pub fn validate(&self) -> Result<()> {
        for (label, filter) in [("user filter", &self.user_filter), ("group filter", &self.group_filter)] {
            if let Some(f) = filter {
                validate_filter(label, f)?;
            }
        }
        Ok(())
    }
}

/// A filter must be parenthesised and parse as RFC 4515.
pub fn validate_filter(label: &str, filter: &str) -> Result<()> {
    if !filter.starts_with('(') || ldap3::parse_filter(filter).is_err() {
        return Err(Error::Validation(format!(
            "invalid {label} {filter:?}; expected e.g. (objectClass=person)"
        )));
    }
    Ok(())
}

/// `dc=example,dc=org` → `example.org`. Returns `None` unless the DN is made
/// only of `dc=` components.
pub fn domain_from_dn(dn: &str) -> Option<String> {
    let parts: Vec<&str> = dn
        .split(',')
        .map(|rdn| rdn.trim())
        .map(|rdn| {
            let (k, v) = rdn.split_once('=')?;
            k.trim().eq_ignore_ascii_case("dc").then(|| v.trim())
        })
        .collect::<Option<_>>()?;
    (!parts.is_empty()).then(|| parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_derivation() {
        assert_eq!(domain_from_dn("dc=example,dc=org").as_deref(), Some("example.org"));
        assert_eq!(domain_from_dn("DC=a, DC=b,dc=c").as_deref(), Some("a.b.c"));
        assert_eq!(domain_from_dn("o=Example,c=ES"), None);
        assert_eq!(domain_from_dn(""), None);
    }

    #[test]
    fn defaults_from_base_dn() {
        let c = Conventions::resolve("dc=example,dc=org", &ConventionsConfig::default());
        assert_eq!(c.people_base, "ou=people,dc=example,dc=org");
        assert_eq!(c.groups_base, "ou=groups,dc=example,dc=org");
        assert_eq!(c.mail_domain.as_deref(), Some("example.org"));
        assert_eq!(c.user_filter, DEFAULT_USER_FILTER);
        assert_eq!(c.group_filter, DEFAULT_GROUP_FILTER);
    }

    #[test]
    fn filters_are_validated() {
        let ok =
            ConventionsConfig { user_filter: Some("(objectClass=account)".into()), ..Default::default() };
        assert!(ok.validate().is_ok());
        for bad in ["objectClass=account", "(objectClass=account", "(&(a=b)"] {
            let cfg = ConventionsConfig { group_filter: Some(bad.into()), ..Default::default() };
            assert!(cfg.validate().is_err(), "{bad}");
        }
        assert!(validate_filter("f", DEFAULT_USER_FILTER).is_ok());
        assert!(validate_filter("f", DEFAULT_GROUP_FILTER).is_ok());
    }

    #[test]
    fn overrides_win() {
        let cfg = ConventionsConfig {
            people_base: Some("ou=staff,dc=x".into()),
            mail_domain: Some("mail.x".into()),
            ..Default::default()
        };
        let c = Conventions::resolve("dc=x", &cfg);
        assert_eq!(c.people_base, "ou=staff,dc=x");
        assert_eq!(c.groups_base, "ou=groups,dc=x");
        assert_eq!(c.mail_domain.as_deref(), Some("mail.x"));
    }
}

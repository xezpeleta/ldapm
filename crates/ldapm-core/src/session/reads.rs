//! Read-only directory queries. Every value interpolated into a filter goes
//! through `ldap_escape`; nothing here can modify the directory.

use std::collections::{BTreeSet, HashMap};

use futures_util::stream::{self, StreamExt, TryStreamExt};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry, ldap_escape};
use serde::Serialize;

use super::Session;
use crate::conventions::PERMANENT_LOCK;
use crate::error::map_ldap;
use crate::{Error, Result};

const PAGE_SIZE: i32 = 200;
/// OR-filters for member existence checks are split into chunks of this size.
const FILTER_CHUNK: usize = 100;
/// Concurrent base reads when checking DN-valued members.
const DN_CHECKS_IN_FLIGHT: usize = 16;

/// Membership attributes of `posixGroup`, `groupOfNames` and `groupOfUniqueNames`.
const MEMBER_ATTRS: &[&str] = &["memberUid", "member", "uniqueMember"];

/// Attributes whose values are never shown, even if the ACLs allow reading them.
const HIDDEN_ATTRS: &[&str] = &["userpassword", "authpassword", "sambantpassword", "sambalmpassword"];

const PWD_ATTRS: &[&str] = &[
    "pwdAccountLockedTime",
    "pwdAccountTmpLockoutEnd",
    "pwdPolicySubentry",
    "pwdReset",
    "pwdChangedTime",
    "pwdFailureTime",
];

#[derive(Debug, Clone, Serialize)]
pub struct Children {
    pub nodes: Vec<TreeNode>,
    /// True when the server's size limit cut the listing short.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub dn: String,
    pub rdn: String,
    /// From `hasSubordinates`; `None` when the server does not provide it.
    pub has_children: Option<bool>,
    pub object_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Value {
    Text { value: String },
    Binary { len: usize },
    Hidden,
}

#[derive(Debug, Clone, Serialize)]
pub struct Attr {
    pub name: String,
    pub values: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub dn: String,
    pub attrs: Vec<Attr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchField {
    Uid,
    Cn,
    Mail,
    Any,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntrySummary {
    pub dn: String,
    pub uid: Option<String>,
    pub cn: Option<String>,
    pub mail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    /// Administrator-set permanent lock (`pwdAccountLockedTime: 000001010000Z`).
    Disabled,
    /// ppolicy lockout after failed binds; clears by itself or on unlock.
    LockedOut {
        since: String,
        until: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupRef {
    pub dn: String,
    pub cn: String,
    /// The user's primary group (matching `gidNumber`) rather than a listed membership.
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub dn: String,
    pub uid: String,
    pub cn: Option<String>,
    pub mail: Option<String>,
    pub uid_number: Option<String>,
    pub gid_number: Option<String>,
    pub groups: Vec<GroupRef>,
    pub status: UserStatus,
    pub policy: Option<String>,
    pub pwd_reset: bool,
    pub pwd_changed: Option<String>,
    pub failed_binds: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupSummary {
    pub dn: String,
    pub cn: String,
    pub gid_number: Option<String>,
    pub member_count: usize,
}

/// The attribute a membership is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MemberAttr {
    /// RFC 2307 `posixGroup`: the member's uid.
    MemberUid,
    /// RFC 4519 `groupOfNames`: the member's DN.
    Member,
    /// RFC 4519 `groupOfUniqueNames`: the member's DN, optionally with `#'…'B`.
    UniqueMember,
}

#[derive(Debug, Clone, Serialize)]
pub struct Member {
    /// As stored: a uid for `memberUid`, a DN otherwise.
    pub value: String,
    pub attr: MemberAttr,
    /// False for a dangling reference: no such user (uid) or no such entry (DN).
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub dn: String,
    pub cn: String,
    pub object_classes: Vec<String>,
    pub gid_number: Option<String>,
    pub description: Option<String>,
    pub members: Vec<Member>,
}

impl Session {
    /// One-level children of `dn`. Never loads more than one level. A size
    /// limit yields a partial listing marked `truncated` rather than an error,
    /// since browsing a partial level is still useful.
    pub async fn list_children(&self, dn: &str) -> Result<Children> {
        let attrs = ["hasSubordinates", "objectClass"];
        let (entries, truncated) =
            self.search_paged(dn, Scope::OneLevel, "(objectClass=*)", &attrs, true).await?;
        let mut nodes: Vec<TreeNode> = entries
            .into_iter()
            .map(|e| TreeNode {
                rdn: e.dn.split(',').next().unwrap_or(&e.dn).to_string(),
                has_children: first(&e, "hasSubordinates").map(|v| v.eq_ignore_ascii_case("TRUE")),
                object_classes: values(&e, "objectClass"),
                dn: e.dn,
            })
            .collect();
        nodes.sort_by_key(|n| n.rdn.to_lowercase());
        Ok(Children { nodes, truncated })
    }

    /// All attributes of one entry; operational attributes on request.
    pub async fn get_entry(&self, dn: &str, operational: bool) -> Result<Entry> {
        let attrs: &[&str] = if operational { &["*", "+"] } else { &["*"] };
        let e = self.read_base(dn, attrs).await?;
        Ok(to_entry(e))
    }

    /// Substring search on uid/cn/mail below `base` (subtree).
    pub async fn search(&self, base: &str, term: &str, field: SearchField) -> Result<Vec<EntrySummary>> {
        let filter = substring_filter(term, field)?;
        let mut out: Vec<EntrySummary> = self
            .search_all(base, Scope::Subtree, &filter, &["uid", "cn", "mail"])
            .await?
            .into_iter()
            .map(|e| EntrySummary {
                uid: first(&e, "uid").map(str::to_string),
                cn: first(&e, "cn").map(str::to_string),
                mail: first(&e, "mail").map(str::to_string),
                dn: e.dn,
            })
            .collect();
        out.sort_by_key(|e| e.dn.to_lowercase());
        Ok(out)
    }

    /// Users below the people base matching a substring of uid/cn/mail.
    pub async fn search_users(&self, term: &str) -> Result<Vec<EntrySummary>> {
        let filter =
            format!("(&{}{})", self.conventions.user_filter, substring_filter(term, SearchField::Any)?);
        let base = self.conventions.people_base.clone();
        let mut out: Vec<EntrySummary> = self
            .search_all(&base, Scope::Subtree, &filter, &["uid", "cn", "mail"])
            .await?
            .into_iter()
            .map(|e| EntrySummary {
                uid: first(&e, "uid").map(str::to_string),
                cn: first(&e, "cn").map(str::to_string),
                mail: first(&e, "mail").map(str::to_string),
                dn: e.dn,
            })
            .collect();
        out.sort_by(|a, b| a.uid.cmp(&b.uid));
        Ok(out)
    }

    /// Number of entries below the people base matching the user filter.
    pub async fn count_users(&self) -> Result<usize> {
        let base = self.conventions.people_base.clone();
        Ok(self.search_all(&base, Scope::Subtree, &self.conventions.user_filter, &["1.1"]).await?.len())
    }

    /// Look up a user by exact uid, with group memberships and password state.
    pub async fn get_user(&self, uid: &str) -> Result<User> {
        validate_uid(uid)?;
        let mut attrs: Vec<&str> = vec!["uid", "cn", "mail", "uidNumber", "gidNumber"];
        attrs.extend_from_slice(PWD_ATTRS);
        let filter = format!("(&{}(uid={}))", self.conventions.user_filter, ldap_escape(uid));
        let base = self.conventions.people_base.clone();
        let mut found = self.search_all(&base, Scope::Subtree, &filter, &attrs).await?;
        let e = match found.len() {
            0 => return Err(Error::NotFound(format!("user \"{uid}\""))),
            1 => found.remove(0),
            n => return Err(Error::Validation(format!("{n} entries have uid \"{uid}\"; refusing to guess"))),
        };

        let gid = first(&e, "gidNumber").map(str::to_string);
        let groups = self.groups_of(&e.dn, uid, gid.as_deref()).await?;
        Ok(User {
            uid: first(&e, "uid").unwrap_or(uid).to_string(),
            cn: first(&e, "cn").map(str::to_string),
            mail: first(&e, "mail").map(str::to_string),
            uid_number: first(&e, "uidNumber").map(str::to_string),
            gid_number: gid,
            groups,
            status: user_status(first(&e, "pwdAccountLockedTime"), first(&e, "pwdAccountTmpLockoutEnd")),
            policy: first(&e, "pwdPolicySubentry").map(str::to_string),
            pwd_reset: first(&e, "pwdReset").is_some_and(|v| v.eq_ignore_ascii_case("TRUE")),
            pwd_changed: first(&e, "pwdChangedTime").map(str::to_string),
            failed_binds: attr(&e, "pwdFailureTime").map_or(0, Vec::len),
            dn: e.dn,
        })
    }

    /// Groups listing the user by uid (`memberUid`) or DN (`member`,
    /// `uniqueMember`), plus the primary group by `gidNumber`.
    pub async fn groups_of(&self, dn: &str, uid: &str, gid_number: Option<&str>) -> Result<Vec<GroupRef>> {
        let (uid, dn) = (ldap_escape(uid), ldap_escape(dn));
        let mut alts = format!("(memberUid={uid})(member={dn})(uniqueMember={dn})");
        if let Some(gid) = gid_number {
            alts.push_str(&format!("(gidNumber={})", ldap_escape(gid)));
        }
        let filter = format!("(&{}(|{alts}))", self.conventions.group_filter);
        let base = self.conventions.groups_base.clone();
        let mut groups: Vec<GroupRef> = self
            .search_all(&base, Scope::Subtree, &filter, &["cn", "gidNumber"])
            .await?
            .into_iter()
            .filter_map(|e| {
                let cn = first(&e, "cn")?.to_string();
                let primary = gid_number.is_some() && first(&e, "gidNumber") == gid_number;
                Some(GroupRef { dn: e.dn, cn, primary })
            })
            .collect();
        groups.sort_by(|a, b| b.primary.cmp(&a.primary).then_with(|| a.cn.cmp(&b.cn)));
        Ok(groups)
    }

    pub async fn list_groups(&self) -> Result<Vec<GroupSummary>> {
        let base = self.conventions.groups_base.clone();
        let mut attrs = vec!["cn", "gidNumber"];
        attrs.extend_from_slice(MEMBER_ATTRS);
        let mut out: Vec<GroupSummary> = self
            .search_all(&base, Scope::Subtree, &self.conventions.group_filter, &attrs)
            .await?
            .into_iter()
            .map(|e| GroupSummary {
                cn: first(&e, "cn").unwrap_or_default().to_string(),
                gid_number: first(&e, "gidNumber").map(str::to_string),
                member_count: MEMBER_ATTRS.iter().map(|a| values(&e, a).len()).sum(),
                dn: e.dn,
            })
            .collect();
        out.sort_by(|a, b| a.cn.cmp(&b.cn));
        Ok(out)
    }

    /// One group with its members, flagging references to users or entries
    /// that do not exist.
    pub async fn get_group(&self, cn: &str) -> Result<Group> {
        let filter = format!("(&{}(cn={}))", self.conventions.group_filter, ldap_escape(cn));
        let base = self.conventions.groups_base.clone();
        let mut attrs = vec!["cn", "objectClass", "gidNumber", "description"];
        attrs.extend_from_slice(MEMBER_ATTRS);
        let mut found = self.search_all(&base, Scope::Subtree, &filter, &attrs).await?;
        let e = match found.len() {
            0 => return Err(Error::NotFound(format!("group \"{cn}\""))),
            1 => found.remove(0),
            n => return Err(Error::Validation(format!("{n} groups are named \"{cn}\"; refusing to guess"))),
        };

        let uids = values(&e, "memberUid");
        let existing = self.existing_uids(&uids).await?;
        let mut members: Vec<Member> = uids
            .into_iter()
            .map(|uid| Member {
                exists: existing.contains(&uid.to_lowercase()),
                value: uid,
                attr: MemberAttr::MemberUid,
            })
            .collect();
        let dns: Vec<(MemberAttr, String)> = values(&e, "member")
            .into_iter()
            .map(|v| (MemberAttr::Member, v))
            .chain(values(&e, "uniqueMember").into_iter().map(|v| (MemberAttr::UniqueMember, v)))
            .collect();
        let existing: Vec<bool> =
            stream::iter(dns.iter().map(|(_, v)| self.entry_exists(strip_unique_id(v))))
                .buffered(DN_CHECKS_IN_FLIGHT)
                .try_collect()
                .await?;
        members.extend(dns.into_iter().zip(existing).map(|((attr, value), exists)| Member {
            value,
            attr,
            exists,
        }));
        members.sort_by_key(|m| m.value.to_lowercase());
        Ok(Group {
            cn: first(&e, "cn").unwrap_or(cn).to_string(),
            object_classes: values(&e, "objectClass"),
            gid_number: first(&e, "gidNumber").map(str::to_string),
            description: first(&e, "description").map(str::to_string),
            members,
            dn: e.dn,
        })
    }

    /// Which of `uids` exist below the people base (lower-cased; uid matching is case-insensitive).
    async fn existing_uids(&self, uids: &[String]) -> Result<BTreeSet<String>> {
        let base = self.conventions.people_base.clone();
        let mut found = BTreeSet::new();
        for chunk in uids.chunks(FILTER_CHUNK) {
            let alts: String = chunk.iter().map(|u| format!("(uid={})", ldap_escape(u.as_str()))).collect();
            let filter = format!("(&{}(|{alts}))", self.conventions.user_filter);
            for e in self.search_all(&base, Scope::Subtree, &filter, &["uid"]).await? {
                if let Some(uids) = attr(&e, "uid") {
                    found.extend(uids.iter().map(|u| u.to_lowercase()));
                }
            }
        }
        Ok(found)
    }

    /// Whether `dn` names an existing entry. A DN the server cannot parse
    /// counts as missing: it is a dangling reference either way.
    async fn entry_exists(&self, dn: &str) -> Result<bool> {
        let res =
            self.ldap().search(dn, Scope::Base, "(objectClass=*)", vec!["1.1"]).await.map_err(map_ldap)?;
        match res.1.rc {
            0 => Ok(!res.0.is_empty()),
            32 | 34 => Ok(false),
            _ => Err(Error::from_result(&res.1)),
        }
    }

    /// Base-scope read; `noSuchObject` becomes `NotFound`.
    async fn read_base(&self, dn: &str, attrs: &[&str]) -> Result<SearchEntry> {
        let res =
            self.ldap().search(dn, Scope::Base, "(objectClass=*)", attrs.to_vec()).await.map_err(map_ldap)?;
        match res.success() {
            Ok((mut entries, _)) if !entries.is_empty() => Ok(SearchEntry::construct(entries.remove(0))),
            Ok(_) => Err(Error::NotFound(format!("entry \"{dn}\""))),
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => {
                Err(Error::NotFound(format!("entry \"{dn}\"")))
            }
            Err(e) => Err(map_ldap(e)),
        }
    }

    /// Paged search returning every entry (RFC 2696). Hitting the server's
    /// size limit is an error: callers that check membership or uniqueness
    /// must never act on a partial result.
    async fn search_all(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        Ok(self.search_paged(base, scope, filter, attrs, false).await?.0)
    }

    /// Paged search; with `allow_partial`, a size limit returns what arrived
    /// plus `true` instead of failing.
    async fn search_paged(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        allow_partial: bool,
    ) -> Result<(Vec<SearchEntry>, bool)> {
        let attrs: Vec<String> = attrs.iter().map(|a| a.to_string()).collect();
        let adapters: Vec<Box<dyn Adapter<String, Vec<String>>>> =
            vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(PAGE_SIZE))];
        let mut ldap = self.ldap();
        let mut stream =
            ldap.streaming_search_with(adapters, base, scope, filter, attrs).await.map_err(map_ldap)?;
        let mut out = Vec::new();
        while let Some(re) = stream.next().await.map_err(map_ldap)? {
            out.push(SearchEntry::construct(re));
        }
        let res = stream.finish().await;
        match res.rc {
            0 => Ok((out, false)),
            4 if allow_partial => Ok((out, true)),
            4 => Err(Error::SizeLimit { base: base.to_string(), returned: out.len() }),
            32 => Err(Error::NotFound(format!("base \"{base}\""))),
            _ => Err(Error::from_result(&res)),
        }
    }
}

/// Attribute names are case-insensitive and servers differ in the case they return.
fn attr<'a>(e: &'a SearchEntry, name: &str) -> Option<&'a Vec<String>> {
    e.attrs.get(name).or_else(|| e.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

fn first<'a>(e: &'a SearchEntry, name: &str) -> Option<&'a str> {
    attr(e, name).and_then(|v| v.first()).map(String::as_str)
}

fn values(e: &SearchEntry, name: &str) -> Vec<String> {
    attr(e, name).cloned().unwrap_or_default()
}

/// `uniqueMember` may carry an optional unique identifier: `<dn>#'0101'B`.
fn strip_unique_id(value: &str) -> &str {
    match value.rfind("#'") {
        Some(i) if value.ends_with("'B") => &value[..i],
        _ => value,
    }
}

fn to_entry(e: SearchEntry) -> Entry {
    let mut attrs: HashMap<String, Vec<Value>> = HashMap::new();
    for (name, values) in e.attrs {
        let hidden = HIDDEN_ATTRS.contains(&name.to_lowercase().as_str());
        let vals = values
            .into_iter()
            .map(|v| if hidden { Value::Hidden } else { Value::Text { value: v } })
            .collect();
        attrs.insert(name, vals);
    }
    for (name, values) in e.bin_attrs {
        let hidden = HIDDEN_ATTRS.contains(&name.to_lowercase().as_str());
        let vals =
            values.into_iter().map(|v| if hidden { Value::Hidden } else { Value::Binary { len: v.len() } });
        attrs.entry(name).or_default().extend(vals);
    }
    let mut attrs: Vec<Attr> = attrs.into_iter().map(|(name, values)| Attr { name, values }).collect();
    attrs.sort_by(|a, b| {
        let oc = |n: &str| !n.eq_ignore_ascii_case("objectClass");
        oc(&a.name).cmp(&oc(&b.name)).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Entry { dn: e.dn, attrs }
}

/// Distinguish the admin's permanent lock from ppolicy's own temporary lockout.
pub fn user_status(locked_time: Option<&str>, tmp_lockout_end: Option<&str>) -> UserStatus {
    match locked_time {
        None => UserStatus::Active,
        Some(PERMANENT_LOCK) => UserStatus::Disabled,
        Some(since) => {
            UserStatus::LockedOut { since: since.to_string(), until: tmp_lockout_end.map(str::to_string) }
        }
    }
}

fn substring_filter(term: &str, field: SearchField) -> Result<String> {
    let term = term.trim();
    if term.is_empty() {
        return Err(Error::Validation("search term must not be empty".into()));
    }
    let t = ldap_escape(term);
    Ok(match field {
        SearchField::Uid => format!("(uid=*{t}*)"),
        SearchField::Cn => format!("(cn=*{t}*)"),
        SearchField::Mail => format!("(mail=*{t}*)"),
        SearchField::Any => format!("(|(uid=*{t}*)(cn=*{t}*)(mail=*{t}*))"),
    })
}

fn validate_uid(uid: &str) -> Result<()> {
    if uid.is_empty() || uid.len() > 64 || uid.chars().any(|c| c.is_control() || c == '*') {
        return Err(Error::Validation(format!("invalid uid {uid:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status() {
        assert_eq!(user_status(None, None), UserStatus::Active);
        assert_eq!(user_status(Some("000001010000Z"), None), UserStatus::Disabled);
        assert_eq!(
            user_status(Some("20261020101500Z"), Some("20261020102000Z")),
            UserStatus::LockedOut { since: "20261020101500Z".into(), until: Some("20261020102000Z".into()) }
        );
    }

    #[test]
    fn filters_are_escaped() {
        assert_eq!(substring_filter("jo*)(x", SearchField::Uid).unwrap(), r"(uid=*jo\2a\29\28x*)");
        assert_eq!(
            substring_filter(" doe ", SearchField::Any).unwrap(),
            "(|(uid=*doe*)(cn=*doe*)(mail=*doe*))"
        );
        assert!(substring_filter("  ", SearchField::Cn).is_err());
    }

    #[test]
    fn unique_member_id_is_stripped() {
        assert_eq!(strip_unique_id("uid=a,dc=x#'0101'B"), "uid=a,dc=x");
        assert_eq!(strip_unique_id("uid=a,dc=x"), "uid=a,dc=x");
        assert_eq!(strip_unique_id(r"cn=a\#'b,dc=x"), r"cn=a\#'b,dc=x");
    }

    #[test]
    fn passwords_hidden_and_objectclass_first() {
        let mut attrs = HashMap::new();
        attrs.insert("userPassword".to_string(), vec!["{SSHA}xyz".to_string()]);
        attrs.insert("cn".to_string(), vec!["John".to_string()]);
        attrs.insert("objectClass".to_string(), vec!["top".to_string()]);
        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("jpegPhoto".to_string(), vec![vec![0xff, 0xd8, 0x00]]);
        let e = to_entry(SearchEntry { dn: "uid=j".into(), attrs, bin_attrs });
        let names: Vec<&str> = e.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["objectClass", "cn", "jpegPhoto", "userPassword"]);
        assert_eq!(e.attrs[2].values, [Value::Binary { len: 3 }]);
        assert_eq!(e.attrs[3].values, [Value::Hidden]);
    }
}

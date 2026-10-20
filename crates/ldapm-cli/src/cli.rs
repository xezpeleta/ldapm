use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "ldapm", version, about = "Safe, scriptable LDAP directory browser with pinned TLS")]
#[command(propagate_version = true, max_term_width = 100)]
pub struct Cli {
    /// Profile to use (default: the profile marked default, or the only one)
    #[arg(short, long, env = "LDAPM_PROFILE", global = true)]
    pub profile: Option<String>,

    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Read the bind password from the first line of stdin
    #[arg(long, global = true)]
    pub password_stdin: bool,

    /// More logging on stderr (-v, -vv). Secrets are never logged.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub cmd: Cmd,
}

// Parsed once per process; boxing the larger variants buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum Cmd {
    /// Connect, bind and print the identity the server authorized
    Whoami,
    /// Manage connection profiles
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Browse raw directory entries
    #[command(subcommand)]
    Entry(EntryCmd),
    /// Look up users
    #[command(subcommand)]
    User(UserCmd),
    /// Look up groups
    #[command(subcommand)]
    Group(GroupCmd),
}

#[derive(Subcommand)]
pub enum ProfileCmd {
    /// List profiles
    List,
    /// Show one profile with its resolved conventions
    Show { name: Option<String> },
    /// Create a profile
    Add {
        name: String,
        #[command(flatten)]
        conn: ConnArgs,
        /// Make this the default profile
        #[arg(long)]
        default: bool,
    },
    /// Change a profile (only the given options change)
    Edit {
        name: String,
        #[command(flatten)]
        conn: EditArgs,
        /// Make this the default profile
        #[arg(long)]
        default: bool,
        /// Verify the bind password and store it in the Secret Service
        #[arg(long, conflicts_with = "forget_password")]
        remember_password: bool,
        /// Delete the stored bind password and ask every time
        #[arg(long)]
        forget_password: bool,
    },
    /// Delete a profile, its imported CA file and any stored password
    Rm { name: String },
    /// Check tunnel, TLS, bind, base DNs and user/group filters step by step
    Test { name: Option<String> },
}

#[derive(Args)]
pub struct ConnArgs {
    /// Directory host name; must match the server certificate
    #[arg(long)]
    pub host: String,
    /// Port (default 636, or 389 with --starttls)
    #[arg(long)]
    pub port: Option<u16>,
    /// Use ldap:// + StartTLS instead of ldaps://
    #[arg(long)]
    pub starttls: bool,
    /// PEM file with the CA that signed the server certificate (copied into the config dir)
    #[arg(long)]
    pub ca: PathBuf,
    #[arg(long)]
    pub bind_dn: String,
    #[arg(long)]
    pub base_dn: String,
    #[command(flatten)]
    pub ssh: SshArgs,
    #[command(flatten)]
    pub conventions: ConventionArgs,
}

#[derive(Args)]
pub struct EditArgs {
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    /// Switch between StartTLS (true) and ldaps (false)
    #[arg(long)]
    pub starttls: Option<bool>,
    #[arg(long)]
    pub ca: Option<PathBuf>,
    #[arg(long)]
    pub bind_dn: Option<String>,
    #[arg(long)]
    pub base_dn: Option<String>,
    #[command(flatten)]
    pub ssh: SshArgs,
    /// Remove the SSH tunnel from the profile
    #[arg(long, conflicts_with = "ssh")]
    pub no_ssh: bool,
    #[command(flatten)]
    pub conventions: ConventionArgs,
}

#[derive(Args)]
pub struct SshArgs {
    /// Tunnel through this SSH jump host (user@host)
    #[arg(long, value_name = "USER@HOST")]
    pub ssh: Option<String>,
    #[arg(long, requires = "ssh")]
    pub ssh_port: Option<u16>,
    #[arg(long, requires = "ssh")]
    pub ssh_identity: Option<PathBuf>,
    /// known_hosts file pinning the jump host's key (default: ssh's own)
    #[arg(long, requires = "ssh")]
    pub ssh_known_hosts: Option<PathBuf>,
}

#[derive(Args)]
pub struct ConventionArgs {
    /// Default: ou=people,<base-dn>
    #[arg(long)]
    pub people_base: Option<String>,
    /// Default: ou=groups,<base-dn>
    #[arg(long)]
    pub groups_base: Option<String>,
    /// Filter selecting users [default: (|(objectClass=person)(objectClass=posixAccount))]
    #[arg(long, value_name = "FILTER")]
    pub user_filter: Option<String>,
    /// Filter selecting groups [default: posixGroup, groupOfNames or groupOfUniqueNames]
    #[arg(long, value_name = "FILTER")]
    pub group_filter: Option<String>,
    /// Default: derived from the dc= components of the base DN
    #[arg(long)]
    pub mail_domain: Option<String>,
}

#[derive(Subcommand)]
pub enum EntryCmd {
    /// List the children of an entry (default: the base DN)
    Ls { dn: Option<String> },
    /// Show all attributes of an entry
    Show {
        dn: String,
        /// Include operational attributes (pwd*, timestamps, ...)
        #[arg(short, long)]
        operational: bool,
    },
    /// Substring search on uid, cn or mail
    Search {
        term: String,
        /// Search below this DN (default: the base DN)
        #[arg(long)]
        base: Option<String>,
        #[arg(long, value_enum, default_value_t = Field::Any)]
        by: Field,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Field {
    Uid,
    Cn,
    Mail,
    Any,
}

#[derive(Subcommand)]
pub enum UserCmd {
    /// Show a user with groups and password state
    Show { uid: String },
    /// Find users by a substring of uid, cn or mail
    Search { term: String },
}

#[derive(Subcommand)]
pub enum GroupCmd {
    /// List groups with member counts
    List,
    /// Show a group's members, flagging references to missing users or entries
    Show { cn: String },
}

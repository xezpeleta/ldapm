use std::path::PathBuf;

/// Every failure the core can report. Front-ends map `kind()` to exit codes
/// or UI states; `Display` is the message shown to the user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),

    #[error("profile \"{0}\" not found")]
    ProfileNotFound(String),

    #[error("{0}")]
    Validation(String),

    #[error("cannot read CA certificate {path}: {reason}")]
    CaCert { path: PathBuf, reason: String },

    #[error("TLS: {0}")]
    Tls(String),

    /// Could not reach the server or complete the TLS handshake.
    #[error("cannot connect to {url}: {reason}")]
    Connect { url: String, reason: String },

    #[error("SSH tunnel: {0}")]
    Tunnel(String),

    #[error("LDAP: {0}")]
    Ldap(#[from] ldap3::LdapError),

    /// A non-success LDAP result, shown verbatim (server stays the authority).
    #[error("server returned {code} ({name}){}", fmt_text(.text))]
    Server { code: u32, name: &'static str, text: String },

    #[error("{0} not found")]
    NotFound(String),

    /// The server stopped returning entries at its size limit.
    #[error(
        "the server's size limit was reached after {returned} entries below \"{base}\"; \
         the bind DN needs a higher limit (OpenLDAP: olcLimits ... size.prtotal=unlimited)"
    )]
    SizeLimit { base: String, returned: usize },

    #[error("keyring: {0}")]
    Keyring(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

fn fmt_text(text: &str) -> String {
    if text.is_empty() { String::new() } else { format!(": {text}") }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Coarse category, stable across releases, for exit codes and UI branching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad input or local configuration; nothing was sent to the server.
    Usage,
    /// Network, TLS, tunnel or LDAP failure.
    Directory,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Config(_)
            | Error::ProfileNotFound(_)
            | Error::Validation(_)
            | Error::CaCert { .. }
            | Error::Keyring(_)
            | Error::Io { .. } => ErrorKind::Usage,
            Error::Tls(_)
            | Error::Connect { .. }
            | Error::Tunnel(_)
            | Error::Ldap(_)
            | Error::Server { .. }
            | Error::NotFound(_)
            | Error::SizeLimit { .. } => ErrorKind::Directory,
        }
    }

    /// Stable snake_case name of the variant, for machine-readable output.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::ProfileNotFound(_) => "profile_not_found",
            Error::Validation(_) => "invalid_input",
            Error::CaCert { .. } => "ca_cert",
            Error::Tls(_) => "tls",
            Error::Connect { .. } => "connect",
            Error::Tunnel(_) => "tunnel",
            Error::Ldap(_) => "ldap",
            Error::Server { .. } => "server",
            Error::NotFound(_) => "not_found",
            Error::SizeLimit { .. } => "size_limit",
            Error::Keyring(_) => "keyring",
            Error::Io { .. } => "io",
        }
    }

    /// The LDAP result code, for errors the server returned.
    pub fn ldap_code(&self) -> Option<u32> {
        match self {
            Error::Server { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io { context: context.into(), source }
    }

    /// Convert an `LdapResult` with a non-zero code into `Error::Server`.
    pub(crate) fn from_result(res: &ldap3::LdapResult) -> Self {
        Error::Server { code: res.rc, name: rc_name(res.rc), text: res.text.clone() }
    }
}

/// Turn ldap3 errors that wrap a server result into `Error::Server`, so the
/// message carries the code name and the server's diagnostic text.
pub(crate) fn map_ldap(e: ldap3::LdapError) -> Error {
    match e {
        ldap3::LdapError::LdapResult { result } => Error::from_result(&result),
        other => Error::Ldap(other),
    }
}

/// Names for the result codes an admin is likely to see (RFC 4511 §4.1.9).
pub fn rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        19 => "constraintViolation",
        20 => "attributeOrValueExists",
        21 => "invalidAttributeSyntax",
        32 => "noSuchObject",
        34 => "invalidDNSyntax",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        64 => "namingViolation",
        65 => "objectClassViolation",
        66 => "notAllowedOnNonLeaf",
        67 => "notAllowedOnRDN",
        68 => "entryAlreadyExists",
        80 => "other",
        _ => "unknown",
    }
}

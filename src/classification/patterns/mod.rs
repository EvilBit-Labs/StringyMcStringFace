//! Pattern classification modules
//!
//! This module contains submodules for different types of pattern classification:
//! - `ip`: IPv4 and IPv6 address detection
//! - `network`: URL and domain detection
//! - `paths`: File and registry path detection
//! - `data`: GUID, email, Base64, format string, and user agent detection

pub mod data;
pub mod ip;
pub mod network;
pub mod paths;

// Re-export classification functions
pub use data::{
    classify_base64, classify_email, classify_format_string, classify_guid, classify_user_agent,
};
pub use ip::{
    classify_ip_addresses, is_ipv4_address, is_ipv6_address, strip_ipv6_brackets, strip_port,
};
pub use network::{classify_domain, classify_url, has_valid_tld};
pub use paths::{
    classify_posix_path, classify_registry_path, classify_unc_path, classify_windows_path,
    is_suspicious_posix_path, is_suspicious_registry_path, is_suspicious_windows_path,
    is_valid_posix_path, is_valid_registry_path, is_valid_windows_path,
};

// Re-export regex patterns needed by SemanticClassifier for cache testing
pub(crate) use ip::{IPV4_REGEX, IPV6_REGEX};
pub(crate) use network::{DOMAIN_REGEX, URL_REGEX};
pub(crate) use paths::{
    POSIX_PATH_REGEX, REGISTRY_ABBREV_REGEX, REGISTRY_PATH_REGEX, UNC_PATH_REGEX,
    WINDOWS_PATH_REGEX,
};

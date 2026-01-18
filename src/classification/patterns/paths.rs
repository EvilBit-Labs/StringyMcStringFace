//! File and registry path classification patterns
//!
//! This module provides POSIX, Windows, UNC, and registry path detection.

use crate::types::Tag;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Regular expression for matching POSIX file paths
pub(crate) static POSIX_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^/[^\x00\n\r]*").unwrap());

/// Regular expression for matching Windows file paths
pub(crate) static WINDOWS_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z]:\\[^\x00\n\r]*").unwrap());

/// Regular expression for matching UNC network paths
pub(crate) static UNC_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\\\\[a-zA-Z0-9.-]+\\[^\x00\n\r]*").unwrap());

/// Regular expression for matching full Windows registry paths
pub(crate) static REGISTRY_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^HKEY_[A-Z_]+\\[^\x00\n\r]*").unwrap());

/// Regular expression for matching abbreviated registry paths
pub(crate) static REGISTRY_ABBREV_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^HK(LM|CU|CR|U|CC)\\[^\x00\n\r]*").unwrap());

/// Common suspicious POSIX path prefixes for persistence detection
static SUSPICIOUS_POSIX_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "/etc/cron.d/",
        "/etc/init.d/",
        "/usr/local/bin/",
        "/tmp/",
        "/var/tmp/",
        "/etc/rc.d/",
        "/etc/crontab",
        "/etc/systemd/system/",
        "/Library/LaunchDaemons/",
        "/Library/LaunchAgents/",
    ])
});

/// Common suspicious Windows path prefixes for persistence detection
static SUSPICIOUS_WINDOWS_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "C:\\Windows\\System32\\",
        "C:\\Windows\\Temp\\",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        "C:\\Windows\\SysWOW64\\",
    ])
});

/// Known valid POSIX path prefixes
static KNOWN_POSIX_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "/usr/", "/etc/", "/var/", "/home/", "/opt/", "/bin/", "/sbin/", "/lib/", "/dev/",
        "/proc/", "/sys/", "/tmp/",
    ])
});

/// Known valid Windows path prefixes
static KNOWN_WINDOWS_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "C:\\Windows\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\",
        "C:\\Users\\",
        "C:\\ProgramData\\",
    ])
});

/// Valid Windows registry root keys
static VALID_REGISTRY_ROOTS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
        "HKEY_CLASSES_ROOT",
        "HKEY_USERS",
        "HKEY_CURRENT_CONFIG",
    ])
});

/// Suspicious Windows registry paths for persistence detection
static SUSPICIOUS_REGISTRY_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\System\\CurrentControlSet\\Services",
        "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    ])
});

/// Checks if a path contains ASCII case-insensitive substring
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let haystack_bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();

    if needle_bytes.len() > haystack_bytes.len() {
        return false;
    }

    for start in 0..=haystack_bytes.len() - needle_bytes.len() {
        let mut matched = true;
        for i in 0..needle_bytes.len() {
            let hay = haystack_bytes[start + i].to_ascii_lowercase();
            let nee = needle_bytes[i].to_ascii_lowercase();
            if hay != nee {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }

    false
}

fn starts_with_ascii_case_insensitive(text: &str, prefix: &str) -> bool {
    if prefix.len() > text.len() {
        return false;
    }

    text.as_bytes()
        .iter()
        .take(prefix.len())
        .zip(prefix.as_bytes())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

const AUTOSTART_POSIX_SUBPATH: &str = "/.config/autostart/";

/// Checks if text contains printf-style format placeholders
fn contains_printf_placeholder(text: &str) -> bool {
    // Look for common printf patterns that might appear in paths
    let patterns = [
        "%s", "%d", "%x", "%u", "%i", "%f", "%c", "%p", "%n", "%ld", "%lu",
    ];
    patterns.iter().any(|pattern| text.contains(pattern))
}

/// Checks if text contains control characters
fn contains_control_chars(text: &str) -> bool {
    text.chars().any(|c| c.is_control() && c != '\t')
}

/// Validates a POSIX path
pub fn is_valid_posix_path(text: &str) -> bool {
    // Must start with / and have at least one more character
    if !text.starts_with('/') || text.len() < 2 {
        return false;
    }

    // Check for null bytes or control characters
    if contains_control_chars(text) {
        return false;
    }

    // Check for known prefixes to boost confidence
    for prefix in KNOWN_POSIX_PREFIXES.iter() {
        if text.starts_with(prefix) {
            return true;
        }
    }

    // Additional validation for paths that don't start with known prefixes
    // Must have at least one directory separator beyond the root
    if text.len() > 1 && text[1..].contains('/') {
        return true;
    }

    // Single directory under root (e.g., "/bin") - needs to be at least 3 chars
    text.len() >= 3
}

/// Validates a Windows path
pub fn is_valid_windows_path(text: &str) -> bool {
    // Must match the basic pattern
    if !WINDOWS_PATH_REGEX.is_match(text) {
        return false;
    }

    // Check for null bytes or control characters
    if contains_control_chars(text) {
        return false;
    }

    // Validate drive letter is A-Z
    let first_char = text.chars().next().unwrap_or(' ');
    if !first_char.is_ascii_alphabetic() {
        return false;
    }

    // Check for known prefixes to boost confidence
    for prefix in KNOWN_WINDOWS_PREFIXES.iter() {
        if starts_with_ascii_case_insensitive(text, prefix) {
            return true;
        }
    }

    // Path should have at least some content after the drive letter
    text.len() >= 4
}

/// Validates a registry path
pub fn is_valid_registry_path(text: &str) -> bool {
    let upper_text = text.to_uppercase();

    // Check for full registry root
    if upper_text.starts_with("HKEY_") {
        // Extract root key
        if let Some(slash_pos) = text.find('\\') {
            let root = &upper_text[..slash_pos];
            if VALID_REGISTRY_ROOTS.contains(root) {
                return true;
            }
        }
    }

    // Check for abbreviated forms (case-insensitive)
    if REGISTRY_ABBREV_REGEX.is_match(text) {
        return true;
    }

    // Also accept paths that use forward slashes (some tools do this)
    if upper_text.starts_with("HKEY_")
        && text.contains('/')
        && let Some(slash_pos) = text.find('/')
    {
        let root = &upper_text[..slash_pos];
        if VALID_REGISTRY_ROOTS.contains(root) {
            return true;
        }
    }

    false
}

/// Classifies a POSIX path
///
/// # Arguments
/// * `text` - The text to check for POSIX path format
///
/// # Returns
/// Returns `Some(Tag::FilePath)` if valid, `None` otherwise.
pub fn classify_posix_path(text: &str) -> Option<Tag> {
    if POSIX_PATH_REGEX.is_match(text) && is_valid_posix_path(text) {
        Some(Tag::FilePath)
    } else {
        None
    }
}

/// Classifies a Windows path
///
/// # Arguments
/// * `text` - The text to check for Windows path format
///
/// # Returns
/// Returns `Some(Tag::FilePath)` if valid, `None` otherwise.
pub fn classify_windows_path(text: &str) -> Option<Tag> {
    // Skip if it looks like a printf format string
    if contains_printf_placeholder(text) {
        return None;
    }

    if WINDOWS_PATH_REGEX.is_match(text) && is_valid_windows_path(text) {
        Some(Tag::FilePath)
    } else {
        None
    }
}

/// Classifies a UNC network path
///
/// # Arguments
/// * `text` - The text to check for UNC path format
///
/// # Returns
/// Returns `Some(Tag::FilePath)` if valid, `None` otherwise.
pub fn classify_unc_path(text: &str) -> Option<Tag> {
    if UNC_PATH_REGEX.is_match(text) {
        // Basic validation - must have server and share
        let parts: Vec<&str> = text.split('\\').collect();
        // parts[0] and parts[1] are empty (before \\), parts[2] is server, parts[3] is share
        if parts.len() >= 4 && !parts[2].is_empty() && !parts[3].is_empty() {
            return Some(Tag::FilePath);
        }
    }
    None
}

/// Classifies a Windows registry path
///
/// # Arguments
/// * `text` - The text to check for registry path format
///
/// # Returns
/// Returns `Some(Tag::RegistryPath)` if valid, `None` otherwise.
pub fn classify_registry_path(text: &str) -> Option<Tag> {
    // is_valid_registry_path handles both backslash and forward-slash styles
    if is_valid_registry_path(text) {
        Some(Tag::RegistryPath)
    } else {
        None
    }
}

/// Checks if a POSIX path is suspicious (persistence-related)
pub fn is_suspicious_posix_path(text: &str) -> bool {
    if (text.starts_with("/home/") || text.starts_with("/Users/"))
        && text.contains(AUTOSTART_POSIX_SUBPATH)
    {
        return true;
    }
    SUSPICIOUS_POSIX_PATHS.iter().any(|p| text.starts_with(p))
}

/// Checks if a Windows path is suspicious (persistence-related)
pub fn is_suspicious_windows_path(text: &str) -> bool {
    SUSPICIOUS_WINDOWS_PATHS
        .iter()
        .any(|p| starts_with_ascii_case_insensitive(text, p))
}

/// Checks if a registry path is suspicious (persistence-related)
pub fn is_suspicious_registry_path(text: &str) -> bool {
    SUSPICIOUS_REGISTRY_PATHS
        .iter()
        .any(|p| contains_ascii_case_insensitive(text, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_path_valid_and_invalid() {
        assert!(classify_posix_path("/usr/bin/bash").is_some());
        assert!(classify_posix_path("/").is_none());
        assert!(classify_posix_path("not/a/path").is_none());
    }

    #[test]
    fn test_windows_path_valid_and_invalid() {
        assert!(classify_windows_path("C:\\Windows\\System32").is_some());
        assert!(classify_windows_path("/unix/path").is_none());
        assert!(classify_windows_path("1:\\Invalid\\Path").is_none());
    }

    #[test]
    fn test_unc_path_valid_and_invalid() {
        assert!(classify_unc_path("\\\\server\\share\\file.txt").is_some());
        assert!(classify_unc_path("\\\\server").is_none());
    }

    #[test]
    fn test_registry_path_valid_and_invalid() {
        assert!(
            classify_registry_path(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            )
            .is_some()
        );
        assert!(classify_registry_path("HKEY_INVALID\\Path").is_none());
    }

    #[test]
    fn test_suspicious_paths() {
        assert!(is_suspicious_posix_path("/etc/cron.d/malicious"));
        assert!(is_suspicious_windows_path("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_suspicious_registry_path(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
    }
}

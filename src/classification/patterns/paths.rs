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
    let mut set = HashSet::new();
    set.insert("/etc/cron.d/");
    set.insert("/etc/init.d/");
    set.insert("/usr/local/bin/");
    set.insert("/tmp/");
    set.insert("/var/tmp/");
    set.insert("/etc/rc.d/");
    set.insert("/etc/crontab");
    set.insert("/etc/systemd/system/");
    set.insert("~/.config/autostart/");
    set.insert("/Library/LaunchDaemons/");
    set.insert("/Library/LaunchAgents/");
    set
});

/// Common suspicious Windows path prefixes for persistence detection
static SUSPICIOUS_WINDOWS_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("C:\\Windows\\System32\\");
    set.insert("C:\\Windows\\Temp\\");
    set.insert("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\");
    set.insert("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\");
    set.insert("C:\\Windows\\SysWOW64\\");
    set
});

/// Known valid POSIX path prefixes
static KNOWN_POSIX_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("/usr/");
    set.insert("/etc/");
    set.insert("/var/");
    set.insert("/home/");
    set.insert("/opt/");
    set.insert("/bin/");
    set.insert("/sbin/");
    set.insert("/lib/");
    set.insert("/dev/");
    set.insert("/proc/");
    set.insert("/sys/");
    set.insert("/tmp/");
    set
});

/// Known valid Windows path prefixes
static KNOWN_WINDOWS_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("C:\\Windows\\");
    set.insert("C:\\Program Files\\");
    set.insert("C:\\Program Files (x86)\\");
    set.insert("C:\\Users\\");
    set.insert("C:\\ProgramData\\");
    set
});

/// Valid Windows registry root keys
static VALID_REGISTRY_ROOTS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("HKEY_LOCAL_MACHINE");
    set.insert("HKEY_CURRENT_USER");
    set.insert("HKEY_CLASSES_ROOT");
    set.insert("HKEY_USERS");
    set.insert("HKEY_CURRENT_CONFIG");
    set
});

/// Suspicious Windows registry paths for persistence detection
static SUSPICIOUS_REGISTRY_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    set.insert("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    set.insert("\\System\\CurrentControlSet\\Services");
    set.insert("\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    set.insert("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
    set
});

/// Checks if a path contains ASCII case-insensitive substring
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let haystack_lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    haystack_lower.contains(&needle_lower)
}

/// Checks if text contains printf-style format placeholders
fn contains_printf_placeholder(text: &str) -> bool {
    // Look for common printf patterns that might appear in paths
    let patterns = [
        "%s", "%d", "%x", "%u", "%i", "%f", "%c", "%p", "%n", "%ld", "%lu",
    ];
    for pattern in patterns {
        if text.contains(pattern) {
            return true;
        }
    }
    false
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
        if contains_ascii_case_insensitive(text, prefix) {
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
    SUSPICIOUS_POSIX_PATHS.iter().any(|p| text.starts_with(p))
}

/// Checks if a Windows path is suspicious (persistence-related)
pub fn is_suspicious_windows_path(text: &str) -> bool {
    SUSPICIOUS_WINDOWS_PATHS
        .iter()
        .any(|p| contains_ascii_case_insensitive(text, p))
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
    fn test_posix_absolute_path() {
        assert!(classify_posix_path("/usr/bin/bash").is_some());
        assert!(classify_posix_path("/etc/passwd").is_some());
        assert!(classify_posix_path("/home/user/.bashrc").is_some());
    }

    #[test]
    fn test_posix_home_directory() {
        assert!(classify_posix_path("/home/user/documents/file.txt").is_some());
        assert!(classify_posix_path("/Users/admin/Desktop").is_some());
    }

    #[test]
    fn test_posix_with_spaces() {
        assert!(classify_posix_path("/home/user/My Documents/file.txt").is_some());
    }

    #[test]
    fn test_posix_system_directories() {
        assert!(classify_posix_path("/var/log/syslog").is_some());
        assert!(classify_posix_path("/opt/application/bin").is_some());
    }

    #[test]
    fn test_posix_suspicious_paths() {
        assert!(is_suspicious_posix_path("/etc/cron.d/malicious"));
        assert!(is_suspicious_posix_path("/tmp/evil.sh"));
        assert!(!is_suspicious_posix_path("/home/user/normal.txt"));
    }

    #[test]
    fn test_posix_too_short() {
        assert!(classify_posix_path("/").is_none());
        assert!(classify_posix_path("/a").is_none());
    }

    #[test]
    fn test_posix_invalid() {
        assert!(classify_posix_path("not/a/path").is_none());
        assert!(classify_posix_path("C:\\Windows").is_none());
    }

    #[test]
    fn test_posix_with_null_bytes() {
        assert!(classify_posix_path("/path/with\x00null").is_none());
    }

    #[test]
    fn test_windows_absolute_path() {
        assert!(classify_windows_path("C:\\Windows\\System32").is_some());
        assert!(classify_windows_path("D:\\Projects\\code").is_some());
    }

    #[test]
    fn test_windows_program_files() {
        assert!(classify_windows_path("C:\\Program Files\\App\\app.exe").is_some());
        assert!(classify_windows_path("C:\\Program Files (x86)\\App").is_some());
    }

    #[test]
    fn test_windows_with_spaces() {
        assert!(classify_windows_path("C:\\Users\\John Doe\\Documents").is_some());
    }

    #[test]
    fn test_windows_different_drives() {
        assert!(classify_windows_path("D:\\Data\\file.txt").is_some());
        assert!(classify_windows_path("E:\\Backup\\archive.zip").is_some());
    }

    #[test]
    fn test_windows_suspicious_paths() {
        assert!(is_suspicious_windows_path("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_suspicious_windows_path("C:\\Windows\\Temp\\malware.exe"));
        assert!(!is_suspicious_windows_path("D:\\Projects\\code.rs"));
    }

    #[test]
    fn test_windows_case_insensitive() {
        assert!(classify_windows_path("c:\\windows\\system32").is_some());
        assert!(classify_windows_path("C:\\WINDOWS\\SYSTEM32").is_some());
    }

    #[test]
    fn test_windows_invalid() {
        assert!(classify_windows_path("/unix/path").is_none());
        assert!(classify_windows_path("not a path").is_none());
    }

    #[test]
    fn test_windows_invalid_drive() {
        assert!(classify_windows_path("1:\\Invalid\\Path").is_none());
    }

    #[test]
    fn test_unc_path() {
        assert!(classify_unc_path("\\\\server\\share\\file.txt").is_some());
        assert!(classify_unc_path("\\\\192.168.1.1\\c$\\Windows").is_some());
    }

    #[test]
    fn test_unc_with_domain() {
        assert!(classify_unc_path("\\\\domain.local\\share\\path").is_some());
    }

    #[test]
    fn test_unc_invalid() {
        assert!(classify_unc_path("\\\\server").is_none()); // No share
        assert!(classify_unc_path("\\server\\share").is_none()); // Single backslash
    }

    #[test]
    fn test_registry_run_key() {
        assert!(
            classify_registry_path(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            )
            .is_some()
        );
    }

    #[test]
    fn test_registry_current_user() {
        assert!(
            classify_registry_path("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows").is_some()
        );
    }

    #[test]
    fn test_registry_abbreviated_hklm() {
        assert!(
            classify_registry_path("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion").is_some()
        );
    }

    #[test]
    fn test_registry_abbreviated_hkcu() {
        assert!(classify_registry_path("HKCU\\Software\\Classes").is_some());
    }

    #[test]
    fn test_registry_persistence_run() {
        assert!(is_suspicious_registry_path(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
    }

    #[test]
    fn test_registry_invalid_root() {
        assert!(classify_registry_path("HKEY_INVALID\\Path").is_none());
    }

    #[test]
    fn test_registry_forward_slash() {
        assert!(classify_registry_path("HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows").is_some());
    }
}

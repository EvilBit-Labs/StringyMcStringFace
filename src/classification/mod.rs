//! String analysis and tagging
//!
//! This module provides semantic analysis capabilities to identify and tag
//! extracted strings based on their content patterns. The classification system
//! uses pattern matching (regex) combined with validation to reduce false positives.
//!
//! ## Current Capabilities
//!
//! - **IPv4/IPv6 Address Detection**: Identifies IP addresses with support for
//!   ports, bracketed IPv6 notation, and false positive mitigation for version numbers
//! - **URL Detection**: Identifies HTTP/HTTPS URLs
//! - **Domain Detection**: Identifies domain names with TLD validation
//! - **File Path Detection**: Identifies POSIX, Windows, and UNC paths
//! - **Registry Path Detection**: Identifies Windows registry paths
//!
//! ## Future Capabilities
//!
//! - GUIDs/UUIDs
//! - Email addresses
//! - Base64 data
//! - Format strings
//! - User agents
//!
//! ## Usage
//!
//! ```rust
//! use stringy::classification::SemanticClassifier;
//! use stringy::types::{FoundString, Encoding, StringSource, Tag};
//!
//! let classifier = SemanticClassifier::new();
//! let found_string = FoundString {
//!     text: "C:\\Windows\\System32\\cmd.exe".to_string(),
//!     original_text: None,
//!     encoding: Encoding::Ascii,
//!     offset: 0,
//!     rva: None,
//!     section: None,
//!     length: 27,
//!     tags: Vec::new(),
//!     score: 0,
//!     section_weight: None,
//!     semantic_boost: None,
//!     noise_penalty: None,
//!     source: StringSource::SectionData,
//!     confidence: 1.0,
//! };
//!
//! let tags = classifier.classify(&found_string);
//! assert!(tags.contains(&Tag::FilePath));
//! ```

pub mod semantic;
pub use semantic::SemanticClassifier;

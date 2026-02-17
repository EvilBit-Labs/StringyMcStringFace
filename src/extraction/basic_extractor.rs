//! BasicExtractor implementation of the StringExtractor trait
//!
//! This module contains the core extraction engine that orchestrates ASCII, UTF-8,
//! and UTF-16 string extraction across binary sections, applying noise filtering,
//! deduplication, and semantic enrichment.

use crate::types::{
    ContainerInfo, Encoding, FoundString, Result, SectionInfo, SectionType, StringSource,
};

use super::ascii;
use super::config::NoiseFilterConfig;
use super::dedup::{CanonicalString, deduplicate, found_string_to_occurrence};
use super::filters::{CompositeNoiseFilter, FilterContext};
use super::helpers::{apply_semantic_enrichment, extract_ascii_utf8_strings};
use super::traits::{BasicExtractor, ExtractionConfig, StringExtractor};
use super::utf16::{self, ByteOrder};

impl StringExtractor for BasicExtractor {
    fn extract(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>> {
        let mut all_strings = Vec::new();

        // Sort sections by priority from config.section_priority
        let mut sections: Vec<_> = container_info.sections.iter().collect();
        sections.sort_by_key(|section| {
            config
                .section_priority
                .iter()
                .position(|&st| st == section.section_type)
                .unwrap_or_else(|| {
                    // Fallback to section weight (higher weight = higher priority)
                    // Convert weight to usize for consistent key type
                    // Use a large offset to ensure fallback sections sort after prioritized ones
                    let weight_int = (section.weight * 1000.0) as usize;
                    config.section_priority.len() + (10000 - weight_int.min(10000))
                })
        });

        for section in sections {
            // Filter sections based on config
            if section.section_type == SectionType::Debug && !config.include_debug {
                continue;
            }

            // Filter code sections by both type and executable flag
            if (section.section_type == SectionType::Code || section.is_executable)
                && !config.scan_code_sections
            {
                continue;
            }

            // Extract strings from this section
            let section_strings = self.extract_from_section(data, section, config)?;
            all_strings.extend(section_strings);
        }

        // Include import/export symbols if configured
        if config.include_symbols {
            // Add import names
            for import in &container_info.imports {
                let length = import.name.len() as u32;
                all_strings.push(FoundString {
                    text: import.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ImportName,
                    confidence: 1.0,
                });
            }

            // Add export names
            for export in &container_info.exports {
                let length = export.name.len() as u32;
                all_strings.push(FoundString {
                    text: export.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ExportName,
                    confidence: 1.0,
                });
            }
        }

        // Apply demangling and semantic classification before deduplication
        apply_semantic_enrichment(&mut all_strings, container_info);

        // Apply deduplication if enabled
        if config.enable_deduplication {
            let canonical_strings = deduplicate(
                all_strings,
                config.dedup_threshold,
                config.preserve_all_occurrences,
            );
            // Convert canonical strings back to FoundString for backward compatibility
            Ok(canonical_strings
                .into_iter()
                .filter_map(|cs| cs.to_found_string())
                .collect())
        } else {
            Ok(all_strings)
        }
    }

    fn extract_canonical(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<CanonicalString>> {
        let mut all_strings = Vec::new();

        // Sort sections by priority from config.section_priority
        let mut sections: Vec<_> = container_info.sections.iter().collect();
        sections.sort_by_key(|section| {
            config
                .section_priority
                .iter()
                .position(|&st| st == section.section_type)
                .unwrap_or_else(|| {
                    // Fallback to section weight (higher weight = higher priority)
                    // Convert weight to usize for consistent key type
                    // Use a large offset to ensure fallback sections sort after prioritized ones
                    let weight_int = (section.weight * 1000.0) as usize;
                    config.section_priority.len() + (10000 - weight_int.min(10000))
                })
        });

        for section in sections {
            // Filter sections based on config
            if section.section_type == SectionType::Debug && !config.include_debug {
                continue;
            }

            // Filter code sections by both type and executable flag
            if (section.section_type == SectionType::Code || section.is_executable)
                && !config.scan_code_sections
            {
                continue;
            }

            // Extract strings from this section
            let section_strings = self.extract_from_section(data, section, config)?;
            all_strings.extend(section_strings);
        }

        // Include import/export symbols if configured
        if config.include_symbols {
            // Add import names
            for import in &container_info.imports {
                let length = import.name.len() as u32;
                all_strings.push(FoundString {
                    text: import.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ImportName,
                    confidence: 1.0,
                });
            }

            // Add export names
            for export in &container_info.exports {
                let length = export.name.len() as u32;
                all_strings.push(FoundString {
                    text: export.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ExportName,
                    confidence: 1.0,
                });
            }
        }

        // Apply demangling and semantic classification before deduplication
        apply_semantic_enrichment(&mut all_strings, container_info);

        // Apply deduplication if enabled, otherwise convert each string to a canonical form
        if config.enable_deduplication {
            Ok(deduplicate(
                all_strings,
                config.dedup_threshold,
                config.preserve_all_occurrences,
            ))
        } else {
            // Convert each FoundString to a CanonicalString with a single occurrence
            Ok(all_strings
                .into_iter()
                .map(|fs| {
                    let occurrence = found_string_to_occurrence(fs.clone());
                    CanonicalString {
                        text: fs.text,
                        encoding: fs.encoding,
                        occurrences: vec![occurrence],
                        merged_tags: fs.tags,
                        combined_score: fs.score,
                    }
                })
                .collect())
        }
    }

    fn extract_from_section(
        &self,
        data: &[u8],
        section: &SectionInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>> {
        // Early return for zero-sized sections
        if section.size == 0 {
            return Ok(Vec::new());
        }

        // Validate section bounds
        let section_offset = section.offset as usize;
        let section_size = section.size as usize;

        if section_offset >= data.len() {
            return Ok(Vec::new());
        }

        let end_offset = section_offset
            .checked_add(section_size)
            .unwrap_or(data.len())
            .min(data.len());

        let section_data = &data[section_offset..end_offset];

        // Build noise filter config from extraction config
        let noise_filter_config = if config.noise_filtering_enabled {
            Some(NoiseFilterConfig::default())
        } else {
            None
        };

        // Extract ASCII strings only if ASCII encoding is enabled
        // Check both encodings and enabled_encodings fields
        let ascii_enabled = config.encodings.contains(&Encoding::Ascii)
            || config.enabled_encodings.contains(&Encoding::Ascii);

        let mut found_strings = Vec::new();

        if ascii_enabled {
            // Use ASCII extractor for ASCII strings
            let ascii_config = ascii::AsciiExtractionConfig {
                min_length: config.min_ascii_length.max(config.min_length),
                max_length: Some(config.max_length),
            };

            // Extract ASCII strings using the dedicated ASCII extractor with filtering
            found_strings = ascii::extract_from_section(
                section,
                data,
                &ascii_config,
                noise_filter_config.as_ref(),
                config.noise_filtering_enabled,
                config.min_confidence_threshold,
            );
        }

        // For UTF-8 strings, use the existing helper (only if UTF-8 is enabled)
        // Check both encodings and enabled_encodings fields
        let utf8_enabled = config.encodings.contains(&Encoding::Utf8)
            || config.enabled_encodings.contains(&Encoding::Utf8);
        if utf8_enabled {
            let raw_strings =
                extract_ascii_utf8_strings(section_data, config.min_length, config.max_length);

            // Build filter context for UTF-8 strings
            let filter_context = FilterContext::from_section(section);
            let filter = if config.noise_filtering_enabled {
                noise_filter_config.as_ref().map(CompositeNoiseFilter::new)
            } else {
                None
            };

            for (text, relative_offset, length) in raw_strings {
                // Skip if already extracted as ASCII (only if ASCII extraction is enabled)
                if ascii_enabled && text.is_ascii() {
                    continue;
                }

                // Determine encoding
                let encoding = Encoding::Utf8;

                // Filter by configured encodings (check both fields)
                let encoding_allowed = config.encodings.contains(&encoding)
                    || config.enabled_encodings.contains(&encoding);
                if !encoding_allowed {
                    continue;
                }

                // Compute confidence if filtering is enabled
                let confidence = if let Some(ref noise_filter) = filter {
                    noise_filter.calculate_confidence(&text, &filter_context)
                } else {
                    1.0
                };

                // Apply threshold filtering
                if config.noise_filtering_enabled && confidence < config.min_confidence_threshold {
                    continue;
                }

                // Calculate absolute offset
                let absolute_offset = section.offset + relative_offset as u64;

                // Calculate RVA if available
                let rva = section
                    .rva
                    .map(|base_rva| base_rva + relative_offset as u64);

                let found_string = FoundString {
                    text,
                    original_text: None,
                    encoding,
                    offset: absolute_offset,
                    rva,
                    section: Some(section.name.clone()),
                    length: length as u32,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::SectionData,
                    confidence,
                };

                found_strings.push(found_string);
            }
        }

        // For UTF-16 strings, use the UTF-16 extractor (only if UTF-16LE or UTF-16BE is enabled)
        // Check both encodings and enabled_encodings fields
        let utf16le_enabled = config.encodings.contains(&Encoding::Utf16Le)
            || config.enabled_encodings.contains(&Encoding::Utf16Le);
        let utf16be_enabled = config.encodings.contains(&Encoding::Utf16Be)
            || config.enabled_encodings.contains(&Encoding::Utf16Be);

        if utf16le_enabled || utf16be_enabled {
            // Determine which byte order(s) to scan based on enabled encodings and config
            let byte_order = if utf16le_enabled && utf16be_enabled {
                // Both enabled - use config setting (usually Auto)
                config.utf16_byte_order
            } else if utf16le_enabled {
                ByteOrder::LE
            } else {
                ByteOrder::BE
            };

            // Create UTF-16 extraction config
            // Convert max_length from bytes to UTF-16 character count (divide by 2)
            let utf16_max_chars = if config.max_length < 2 {
                Some(0)
            } else {
                Some(config.max_length / 2)
            };
            let utf16_config = utf16::Utf16ExtractionConfig {
                min_length: config.min_wide_length,
                max_length: utf16_max_chars,
                byte_order,
                confidence_threshold: config.utf16_confidence_threshold,
                scan_both_alignments: false, // Default to false to avoid performance degradation
            };

            // Extract UTF-16 strings using the dedicated UTF-16 extractor
            let utf16_strings = utf16::extract_from_section(
                section,
                data,
                &utf16_config,
                noise_filter_config.as_ref(),
                config.noise_filtering_enabled,
                config.utf16_min_confidence,
            );

            found_strings.extend(utf16_strings);
        }

        Ok(found_strings)
    }
}

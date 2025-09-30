# Implementation Plan

- [x] 1. Create foundational project structure and data types

  - Create complete project structure with Cargo.toml, essential dependencies (goblin, clap, serde, serde_json), and module hierarchy (src/container/, src/extraction/, src/classification/, src/output/)
  - Define core data types in src/types.rs including FoundString struct, Encoding enum (Ascii, Utf8, Utf16Le, Utf16Be), Tag enum for semantic classification
  - Define container and section types including SectionType and StringSource enums, ContainerInfo and SectionInfo structs
  - Implement comprehensive error handling framework with StringyError enum and Result type alias
  - _Requirements: 1.1, 1.4, 6.1, 9.1_

- [x] 2. Implement basic format detection and container parsers

  - Create ContainerParser trait and implement format detection for ELF, PE, and Mach-O using goblin
  - Build complete container parser stubs for all three formats (src/container/elf.rs, pe.rs, macho.rs)
  - Implement basic section enumeration for each format with unit tests
  - Add format detection capabilities to distinguish between binary types
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [ ] 3. Implement ELF section classification

  - Enhance ELF parser to classify sections by type (string data vs code vs other)

  - Implement logic to identify .rodata, .data.rel.ro, .comment sections

  - Add section weight assignment based on likelihood of containing meaningful strings

  - _Requirements: 1.1, 1.4_

  - [ ] 3.1 Add ELF import/export extraction

    - Extract import and export symbol names from ELF dynamic section
    - Classify symbols as imports vs exports for proper tagging
    - Add unit tests for symbol extraction
    - _Requirements: 4.2, 4.3_

- [ ] 4. Implement PE section classification

  - Enhance PE parser to classify sections (.rdata, .data) by string likelihood

  - Add section weight assignment for PE-specific sections

  - Implement basic PE import/export table parsing

  - _Requirements: 1.2, 1.4_

  - [ ] 4.1 Add PE resource extraction foundation

    - Add pelite dependency to Cargo.toml
    - Implement basic PE resource enumeration
    - Create framework for extracting VERSIONINFO and STRINGTABLE resources
    - _Requirements: 1.2_

  - [ ] 4.2 Implement PE resource string extraction

    - Extract strings from VERSIONINFO resources
    - Extract strings from STRINGTABLE resources
    - Add manifest resource string extraction
    - _Requirements: 1.2_

- [ ] 5. Implement Mach-O section classification

  - Enhance Mach-O parser to identify string-containing sections

  - Classify \_\_TEXT,\_\_cstring, \_\_TEXT,\_\_const, \_\_DATA_CONST sections

  - Add section weight assignment for Mach-O sections

  - _Requirements: 1.3, 1.4_

  - [ ] 5.1 Add Mach-O load command processing

    - Add object crate dependency for enhanced Mach-O support
    - Extract strings from load commands
    - Implement load command string classification and tagging
    - _Requirements: 1.3_

- [ ] 6. Create string extraction framework

  - Create StringExtractor trait in src/extraction/mod.rs

  - Define RawString struct for extracted string data with metadata

  - Create ExtractionConfig struct for configurable parameters

  - _Requirements: 2.1_

  - [ ] 6.1 Implement basic ASCII string extraction

    - Create src/extraction/ascii.rs with ASCII extraction logic
    - Implement scanning for printable character runs (0x20-0x7E)
    - Add configurable minimum length filtering
    - Add unit tests for basic ASCII extraction
    - _Requirements: 2.1_

  - [ ] 6.2 Add ASCII noise filtering

    - Implement heuristics to distinguish legitimate strings from binary noise
    - Add logic to avoid extracting from obvious padding or table data
    - Consider section context when determining string legitimacy
    - _Requirements: 1.4, 2.1_

- [ ] 7. Implement UTF-16LE string extraction

  - Create src/extraction/utf16.rs with UTF-16LE extraction logic

  - Implement detection of even-length sequences with mostly-zero high bytes

  - Add configurable minimum length for wide character strings

  - Add unit tests for UTF-16LE extraction

  - _Requirements: 2.2_

  - [ ] 7.1 Add UTF-16BE support and confidence scoring

    - Extend UTF-16 extractor to handle big-endian byte order
    - Implement confidence scoring to avoid false positives
    - Add detection of null-interleaved text patterns
    - _Requirements: 2.3, 2.4_

- [ ] 8. Implement string deduplication

  - Create src/extraction/dedup.rs with deduplication logic
  - Implement string canonicalization while preserving metadata
  - Handle multiple instances of same string in different sections
  - Add unit tests for deduplication with metadata preservation
  - _Requirements: 2.5_

- [ ] 9. Create semantic classification framework

  - Create Classifier trait in src/classification/mod.rs

  - Define StringContext struct for classification context

  - Create basic classification pipeline structure

  - _Requirements: 3.1_

  - [ ] 9.1 Implement URL and domain classification

    - Add regex dependency to Cargo.toml
    - Create src/classification/semantic.rs with URL pattern matching
    - Implement domain name detection and validation
    - Add unit tests for URL and domain classification
    - _Requirements: 3.1, 3.2_

  - [ ] 9.2 Implement IP address classification

    - Add IPv4 address pattern matching to semantic classifier
    - Add IPv6 address pattern matching
    - Include unit tests for IP address detection
    - _Requirements: 3.3_

  - [ ] 9.3 Implement file path classification

    - Add POSIX file path pattern matching
    - Add Windows file path pattern matching
    - Include registry path detection
    - Add unit tests for path classification
    - _Requirements: 3.4, 3.5_

  - [ ] 9.4 Implement remaining semantic patterns

    - Add GUID pattern matching
    - Add email address pattern matching
    - Add Base64 pattern detection
    - Add printf-style format string detection
    - Add user agent pattern matching
    - Include comprehensive unit tests
    - _Requirements: 3.6, 3.7, 3.8, 3.9, 3.10_

- [ ] 10. Implement symbol processing

  - Create src/classification/symbols.rs

  - Add rustc-demangle dependency to Cargo.toml

  - Implement basic Rust symbol demangling

  - Add unit tests for symbol demangling

  - _Requirements: 4.1_

  - [ ] 10.1 Add import/export classification

    - Implement import name identification and tagging
    - Implement export name identification and tagging
    - Add section name processing and classification
    - Include unit tests for import/export detection
    - _Requirements: 4.2, 4.3, 4.4_

- [ ] 11. Create ranking system foundation

  - Create src/classification/ranking.rs with RankingEngine struct

  - Define scoring configuration and weight mappings

  - Implement basic score calculation framework

  - _Requirements: 5.1_

  - [ ] 11.1 Implement section weight scoring

    - Add section weight calculation based on SectionType
    - Implement encoding confidence scoring
    - Add unit tests for section-based scoring
    - _Requirements: 5.1, 5.5_

  - [ ] 11.2 Implement semantic boost scoring

    - Add semantic boost calculation for different tag types
    - Implement import/export name boost scoring
    - Add unit tests for semantic boost calculation
    - _Requirements: 5.2, 5.4_

  - [ ] 11.3 Implement noise penalty detection

    - Add high entropy detection and penalty calculation
    - Implement excessive length penalty
    - Add repeated pattern detection
    - Add table data detection heuristics
    - Include unit tests for noise penalty calculation
    - _Requirements: 5.3_

- [ ] 12. Create output formatting framework

  - Create src/output/mod.rs with output formatter traits

  - Define common output interfaces and structures

  - Create output configuration options

  - _Requirements: 6.1_

  - [ ] 12.1 Implement JSONL output format

    - Create src/output/json.rs with JSONL formatter
    - Implement serialization of FoundString with all required fields
    - Add unit tests for JSONL output format
    - _Requirements: 6.1, 6.4_

  - [ ] 12.2 Implement human-readable output

    - Create src/output/human.rs with table formatter
    - Implement sorted table display with proper column alignment
    - Add unit tests for human-readable output
    - _Requirements: 6.2_

  - [ ] 12.3 Implement YARA-friendly output

    - Create src/output/yara.rs with YARA rule formatter
    - Implement proper string escaping for YARA rules
    - Add truncation rules for long strings
    - Include unit tests for YARA output format
    - _Requirements: 6.3_

- [ ] 13. Create basic CLI structure

  - Implement basic CLI argument parsing in src/main.rs using clap

  - Add file input argument and basic error handling

  - Create simple CLI structure with help text

  - _Requirements: 7.7_

  - [ ] 13.1 Add filtering CLI arguments

    - Implement --min-len argument for minimum string length
    - Add --enc argument for encoding selection
    - Add --only-tags and --notags for tag filtering
    - Include unit tests for argument parsing
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [ ] 13.2 Add output format CLI arguments

    - Implement --top argument for result limiting
    - Add --json flag for JSONL output format
    - Set default to human-readable output when no format specified
    - Add integration tests for CLI output format selection
    - _Requirements: 7.5, 7.6, 7.7_

- [ ] 14. Add memory mapping support

  - Add memmap2 dependency to Cargo.toml

  - Implement memory-mapped file reading for large files

  - Add fallback to regular file reading for small files

  - Include unit tests for memory mapping functionality

  - _Requirements: 8.1_

  - [ ] 14.1 Implement regex caching

    - Add regex compilation caching to semantic classifier
    - Implement lazy initialization of regex patterns
    - Add performance benchmarks for regex caching
    - _Requirements: 8.3_

- [ ] 15. Create basic test infrastructure

  - Create tests/fixtures/ directory with sample binary files

  - Add basic integration test framework

  - Create simple ELF, PE, and Mach-O test binaries

  - _Requirements: All requirements validation_

  - [ ] 15.1 Add comprehensive integration tests

    - Add criterion dependency for performance benchmarks
    - Implement end-to-end CLI functionality tests
    - Add insta dependency for snapshot testing
    - Create cross-platform validation tests
    - _Requirements: All requirements validation_

- [ ] 16. Create main extraction pipeline

  - Create main extraction orchestrator in src/lib.rs

  - Wire together format detection, parsing, extraction, classification, and ranking

  - Implement proper error handling throughout the pipeline

  - _Requirements: All requirements integration_

  - [ ] 16.1 Complete pipeline integration

    - Integrate all components with consistent data flow
    - Add comprehensive error recovery mechanisms
    - Implement end-to-end integration tests
    - Validate complete pipeline against all requirements
    - _Requirements: All requirements integration_

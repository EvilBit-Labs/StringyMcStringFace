# Epic Brief: Stringy v1.0 Completion

## Summary

Stringy v1.0 completion transforms a promising foundation into a production-ready binary analysis tool that solves a fundamental problem: existing tools like GNU strings produce overwhelming noise without intelligence. Users across security research, malware analysis, and reverse engineering need format-aware string extraction that automatically identifies meaningful data, ranks results by relevance, and integrates into automated workflows. The current incomplete state forces users to manually filter thousands of strings and decipher cryptic mangled symbols, wasting valuable analysis time. Completing v1.0 delivers semantic classification, intelligent ranking, symbol demangling, and flexible output formats - enabling users to immediately see the most important strings (URLs, file paths, IOCs) ranked by relevance, understand binary functionality through demangled symbols, and integrate Stringy into production analysis pipelines.

## Context & Problem

### Who's Affected

**Primary Users:**
- **Security researchers and malware analysts** who need to quickly identify indicators of compromise (IOCs), behavioral patterns, and malicious infrastructure in binaries
- **Reverse engineers** who need to understand binary functionality, dependencies, and internal structure through string analysis
- **Open-source community** seeking a modern, intelligent alternative to decades-old tools like GNU strings
- **DevOps and security teams** who need to integrate string extraction into automated analysis pipelines

These users share a common need: efficient, intelligent binary analysis that surfaces meaningful information without manual noise filtering.

### Current Pain Points

**Problem 1: Signal vs Noise**
Traditional tools like GNU strings extract every printable character sequence, producing thousands of results where 90%+ are meaningless - padding bytes, binary tables, random data that happens to be printable. Users must manually scan through this noise to find the 10% that matters: URLs, file paths, registry keys, function names. This manual filtering is time-consuming, error-prone, and doesn't scale.

**Problem 2: Cryptic Symbols**
Modern binaries contain mangled symbols (especially Rust, C++) that appear as cryptic strings like `_ZN4core3fmt3num52_$LT$impl$`. Without demangling, users cannot understand what functions are called, what libraries are used, or what the binary actually does. This forces users to copy-paste symbols into external demangling tools, breaking their workflow.

**Problem 3: No Prioritization**
Even when users find potentially interesting strings, they have no way to know which ones are most important. Is this URL critical infrastructure or a help link? Is this file path a configuration file or a debug artifact? Without ranking and context, users waste time investigating low-value strings while missing critical indicators.

**Problem 4: Integration Barriers**
Users cannot integrate the current incomplete tool into automated workflows because it lacks:
- Structured output formats (JSON) for programmatic consumption
- Filtering capabilities to focus on specific string types
- Reliable, production-ready behavior

### Where in the Product

The gaps exist across the entire analysis pipeline:

1. **Classification Layer** (file:src/classification/): Types are defined but semantic pattern matching is not implemented. Users cannot automatically identify URLs, IPs, domains, file paths, GUIDs, emails, Base64, format strings, or user agents.

2. **Symbol Processing** (file:src/classification/): No demangling capability exists. Mangled Rust/C++ symbols remain cryptic and unusable.

3. **Ranking System** (file:src/classification/): No scoring algorithm exists to prioritize strings. All strings are treated equally regardless of their source section, semantic meaning, or likelihood of being meaningful.

4. **Output Formatting** (file:src/output/): Only basic interfaces exist. Users cannot get JSONL for automation, human-readable tables for manual review, or YARA-friendly output for rule creation.

5. **CLI Interface** (file:src/main.rs): Missing filtering options (--min-len, --enc, --only-tags, --notags, --top) and output format selection (--json).

6. **Performance** (file:src/extraction/): No memory mapping for large files, no regex caching for classification patterns.

### The Gap

**Current State:** Stringy has a solid foundation with format detection, container parsing, and basic string extraction working. Users can extract strings from ELF, PE, and Mach-O binaries with encoding awareness (ASCII, UTF-16). However, the output is raw and unprocessed - similar to GNU strings but with better encoding support.

**Desired State:** Users run Stringy on any binary and immediately see:
- All meaningful strings ranked by importance (format-aware filtering removes noise)
- Automatic semantic tags (URL, filepath, ipv4, guid, etc.) highlighting what each string represents
- Demangled symbols showing actual function and type names
- Flexible output formats for both manual analysis and automated integration
- Production-ready reliability for daily use

**User Feedback:** "I want to use Stringy but it's not ready yet. I need it to tell me what's important, not just dump everything."

### Success Criteria

When v1.0 is complete, users will be able to:
1. Run Stringy on a binary and immediately see the most relevant strings ranked by importance
2. Quickly identify IOCs, file paths, URLs, and other semantic patterns without manual searching
3. Understand binary functionality through demangled symbols and import/export analysis
4. Integrate Stringy into automated analysis pipelines with proper filtering and output formats
5. Rely on Stringy as a production-ready tool for daily binary analysis work

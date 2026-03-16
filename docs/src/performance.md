# Performance

Stringy is designed for efficient analysis of binary files, from small executables to large system libraries.

## How It Works

Stringy memory-maps input files via [mmap-guard] for zero-copy access, then processes sections in weight-priority order. Regex patterns for semantic classification are compiled once using `LazyLock` statics.

The processing pipeline is single-threaded and sequential:

1. **Format detection and section analysis** -- O(n) where n = number of sections
2. **String extraction** -- O(m) where m = total section size
3. **Deduplication** -- hash-based grouping of identical strings
4. **Classification** -- O(k) where k = number of unique strings
5. **Ranking and sorting** -- O(k log k)

## Reducing Processing Time

Use CLI flags to narrow the work Stringy does:

```bash
# Limit to top results (skip sorting the long tail)
stringy --top 50 binary

# Increase minimum length to reduce noise and string count
stringy --min-len 8 binary

# Restrict to a single encoding (skip UTF-16 detection)
stringy --enc ascii binary

# Skip classification and ranking entirely
stringy --raw binary
```

`--raw` mode is the fastest option -- it extracts and deduplicates strings without running the classifier or ranker.

## Benchmarking

Stringy includes [Criterion](https://docs.rs/criterion) benchmarks for core components:

```bash
# Run all benchmarks
just bench

# Run a specific benchmark
cargo bench --bench elf
cargo bench --bench pe
cargo bench --bench classification
cargo bench --bench ascii_extraction
```

## Profiling

```bash
# CPU profiling with perf (Linux)
perf record --call-graph dwarf -- stringy large_file.exe
perf report

# macOS profiling with Instruments
xcrun xctrace record --template "Time Profiler" --launch -- stringy binary

# Memory profiling
/usr/bin/time -l stringy large_file.exe   # macOS
/usr/bin/time -v stringy large_file.exe   # Linux
```

## Batch Processing

Stringy processes one file per invocation. For batch workflows, use standard Unix tools:

```bash
# Process multiple files
find /path/to/binaries -type f -exec stringy --json {} \; > all_strings.jsonl

# Parallel processing with xargs
find /binaries -name "*.exe" -print0 | xargs -0 -P 4 -I {} stringy --json {} > results.jsonl
```

[mmap-guard]: https://docs.rs/mmap-guard

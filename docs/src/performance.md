# Performance

Stringy is designed for efficient analysis of binary files, from small executables to large system libraries. This guide covers performance characteristics, optimization techniques, and best practices.

## Performance Overview

### Typical Performance

| File Size | Processing Time | Memory Usage | Notes                          |
| --------- | --------------- | ------------ | ------------------------------ |
| < 1MB     | < 100ms         | < 10MB       | Small executables              |
| 1-10MB    | 100ms - 1s      | 10-50MB      | Typical applications           |
| 10-100MB  | 1-10s           | 50-200MB     | Large applications, libraries  |
| > 100MB   | 10s+            | 200MB+       | System libraries, packed files |

### Factors Affecting Performance

1. **File size**: Larger files take longer to process
2. **Section count**: More sections require more analysis
3. **String density**: Files with many strings take longer
4. **Encoding complexity**: UTF-16 detection is more expensive than ASCII
5. **Classification depth**: More semantic patterns increase processing time

## Memory Management

### Memory Mapping

Stringy uses memory mapping for efficient file access:

```rust
// Automatic memory mapping for large files
if file_size > MEMORY_MAP_THRESHOLD {
    let mmap = unsafe { Mmap::map(&file)? };
    process_data(&mmap[..])
} else {
    let data = std::fs::read(path)?;
    process_data(&data)
}
```

**Benefits:**

- Reduced memory usage for large files
- Faster access to file data
- OS-level caching optimization

**Configuration:**

```bash
# Adjust memory mapping threshold
stringy --mmap-threshold 5MB large_file.exe

# Disable memory mapping
stringy --no-mmap file.exe
```

### Memory Usage Patterns

```
Peak Memory = Base Memory + File Size + String Storage + Classification Data
```

- **Base Memory**: ~5-10MB for the application
- **File Size**: Full file size if not memory-mapped
- **String Storage**: ~2-5x the total extracted string length
- **Classification Data**: ~1-2MB for regex engines and caches

### Memory Optimization

```bash
# Limit string length to reduce memory usage
stringy --max-len 200 large_file.exe

# Limit results to reduce output memory
stringy --top 100 large_file.exe

# Process specific sections only
stringy --sections .rodata,.rdata large_file.exe
```

## CPU Performance

### Single-Threaded Performance

Core extraction pipeline is optimized for single-threaded performance:

1. **Section Analysis**: O(n) where n = number of sections
2. **String Extraction**: O(m) where m = total section size
3. **Classification**: O(k) where k = number of extracted strings
4. **Ranking**: O(k log k) for sorting

### Parallel Processing

Future versions will support parallel processing:

```rust
// Planned parallel section processing
sections.par_iter()
    .flat_map(|section| extract_from_section(section, data))
    .collect()
```

**Parallelization opportunities:**

- Section-level extraction
- Classification of string batches
- Multiple file processing

### CPU Optimization Techniques

#### Regex Caching

```rust
lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r"https?://[^\s]+").unwrap();
    static ref DOMAIN_REGEX: Regex = Regex::new(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
}
```

#### Efficient String Scanning

```rust
// Optimized ASCII scanning with SIMD potential
fn scan_ascii_optimized(data: &[u8]) -> Vec<StringMatch> {
    let mut matches = Vec::new();
    let mut current_start = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_start.is_none() {
                current_start = Some(i);
            }
        } else if let Some(start) = current_start.take() {
            if i - start >= MIN_LENGTH {
                matches.push(StringMatch { start, end: i });
            }
        }
    }

    matches
}
```

## I/O Performance

### File Access Patterns

Stringy uses sequential access patterns optimized for modern storage:

```rust
// Sequential section processing
for section in container.sections {
    let section_data = &data[section.offset..section.offset + section.size];
    process_section(section_data);
}
```

### Storage Type Impact

| Storage Type | Relative Performance | Notes                              |
| ------------ | -------------------- | ---------------------------------- |
| NVMe SSD     | 1.0x (baseline)      | Optimal performance                |
| SATA SSD     | 0.8-0.9x             | Good performance                   |
| HDD          | 0.3-0.5x             | Slower, especially for large files |
| Network      | 0.1-0.3x             | Highly variable                    |

### I/O Optimization

```bash
# Process from faster storage when possible
cp /slow/path/binary /tmp/binary
stringy /tmp/binary

# Use memory mapping for network files
stringy --force-mmap network_file.exe
```

## Optimization Strategies

### For Interactive Use

Optimize for fast feedback:

```bash
# Quick scan of high-value sections
stringy --sections .rodata,.rdata --top 20 binary.exe

# ASCII only for faster processing
stringy --enc ascii --min-len 6 binary.exe

# Skip expensive classification
stringy --no-classify --json binary.exe | jq '.[] | select(.length > 10)'
```

### For Batch Processing

Optimize for throughput:

```bash
# Process multiple files efficiently
find /binaries -name "*.exe" -exec stringy --json {} \; > all_strings.jsonl

# Use minimal output for large batches
stringy --json --no-metadata --top 10 *.dll

# Parallel processing with xargs
find /binaries -name "*.so" | xargs -P 4 -I {} stringy --json {} > results.jsonl
```

### For Large Files

Handle large files efficiently:

```bash
# Focus on high-value sections
stringy --sections .rodata,.rdata,.rsrc huge_file.exe

# Increase minimum length to reduce noise
stringy --min-len 8 --top 50 huge_file.exe

# Use streaming output for very large results
stringy --json huge_file.exe | head -1000 > sample.jsonl
```

## Performance Monitoring

### Built-in Timing

```bash
# Enable timing information
stringy --timing binary.exe
```

Output includes:

- File loading time
- Format detection time
- Section analysis time
- String extraction time
- Classification time
- Output formatting time

### Memory Profiling

```bash
# Monitor memory usage (Unix systems)
/usr/bin/time -v stringy large_file.exe

# macOS
/usr/bin/time -l stringy large_file.exe
```

### Benchmarking

Use the built-in benchmark suite:

```bash
# Run performance benchmarks
cargo bench

# Benchmark specific components
cargo bench --bench extraction
cargo bench --bench classification
```

## Performance Tuning

### Configuration Tuning

```toml
[performance]
# Memory mapping threshold (bytes)
memory_map_threshold = 10485760 # 10MB

# Maximum memory usage (bytes)
max_memory_usage = 1073741824 # 1GB

# String extraction chunk size
chunk_size = 1048576 # 1MB

# Enable performance optimizations
fast_mode = true
skip_low_confidence = true
```

### Runtime Tuning

```bash
# Adjust for available memory
export STRINGY_MAX_MEMORY=512MB

# Tune for CPU cores
export STRINGY_THREADS=4

# Enable aggressive caching
export STRINGY_CACHE_SIZE=100MB
```

## Bottleneck Analysis

### Common Bottlenecks

1. **Large UTF-16 sections**: UTF-16 detection is CPU-intensive
2. **Many small strings**: Classification overhead per string
3. **Complex regex patterns**: Some semantic patterns are expensive
4. **Large output**: JSON serialization and formatting

### Profiling Tools

```bash
# CPU profiling with perf (Linux)
perf record --call-graph dwarf stringy large_file.exe
perf report

# Memory profiling with valgrind
valgrind --tool=massif stringy binary.exe

# macOS profiling with Instruments
instruments -t "Time Profiler" stringy binary.exe
```

## Optimization Examples

### Fast Security Scan

```bash
# Optimized for security indicators
stringy \
  --enc ascii,utf8 \
  --min-len 8 \
  --only url,domain,ipv4,filepath \
  --top 20 \
  --sections .rodata,.rdata \
  malware.exe
```

### Comprehensive Analysis

```bash
# Thorough but efficient analysis
stringy \
  --enc ascii,utf16le \
  --min-len 4 \
  --max-len 500 \
  --top 200 \
  --json \
  application.exe > analysis.jsonl
```

### Batch Processing Script

```bash
#!/bin/bash
# Efficient batch processing

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

for file in "$@"; do
    # Copy to fast storage if needed
    if [[ "$file" == /slow/* ]]; then
        cp "$file" "$TEMP_DIR/"
        file="$TEMP_DIR/$(basename "$file")"
    fi
    
    # Process with optimized settings
    stringy \
      --json \
      --top 50 \
      --min-len 6 \
      --sections .rodata,.rdata,.rsrc \
      "$file" >> results.jsonl
done
```

## Future Optimizations

### Planned Improvements

1. **SIMD acceleration**: Vectorized string scanning
2. **Parallel processing**: Multi-threaded extraction and classification
3. **Incremental analysis**: Cache results for repeated analysis
4. **Streaming processing**: Handle arbitrarily large files
5. **GPU acceleration**: Parallel pattern matching on GPU

### Performance Roadmap

- **v0.2**: Basic parallel processing
- **v0.3**: SIMD-optimized string scanning
- **v0.4**: Incremental analysis and caching
- **v1.0**: Full streaming support

This performance guide helps you get the most out of Stringy for your specific use case, whether you're doing interactive analysis or processing large batches of files.

# Rust Bridge Test Suite

## Overview

This directory contains unit tests for the Rust bridge layer. These tests validate data structures, error handling, serialization, and other non-Python-dependent functionality.

## Test Files

- `types_tests.rs` - Tests for all data structures (ProcessInfo, CommandLineInfo, etc.) and JSON serialization/deserialization
- `error_tests.rs` - Tests for error types and error handling
- More test files to be added...

## Running Tests

### Run All Unit Tests
```bash
cargo test --lib
```

### Run Specific Test File
```bash
cargo test --test types_tests
cargo test --test error_tests
```

### Run With Code Coverage
```bash
cargo tarpaulin --out Html --output-dir target/coverage
```

## Test Organization

### Unit Tests (Fast, No External Dependencies)
Located in `tests/` directory:
- Data structure tests
- Serialization/deserialization tests
- Error handling tests
- String manipulation tests

### Integration Tests (Slow, Require Python/Volatility)
Located in `src/` files with `#[cfg(test)]`:
- `process_analysis.rs` - Contains tests that require actual Volatility execution
- These tests require:
  - Python environment with Volatility 3 installed
  - Valid memory dump file
  - Will fail if run without proper setup

**Note:** Integration tests in src files are expected to fail in CI/CD environments without Python setup. They should be run manually with:
```bash
cargo test --all
```

## Performance Benchmarks

Located in `benches/performance.rs`:

```bash
# Run benchmarks
cargo bench

# View HTML reports
start target/criterion/report/index.html  # Windows
open target/criterion/report/index.html   # macOS
xdg-open target/criterion/report/index.html  # Linux
```

## Test Coverage Goals

- **Unit Tests:** >85% coverage (data structures, error handling, serialization)
- **Integration Tests:** Manual verification with real dumps
- **Benchmarks:** Track performance regressions

## Current Test Status

✅ **Passing:**
- All data structure tests (types_tests.rs)
- All error handling tests (error_tests.rs)
- Benchmarks compile and run

⚠️ **Expected Failures (Integration Tests in src/):**
- `process_analysis::tests::test_list_processes_basic`
- `process_analysis::tests::test_find_process_by_pid`
- `process_analysis::tests::test_find_process_by_name`

These require actual Volatility execution and should be run separately:
```bash
# Set up Python environment first
..\volatility-env\Scripts\Activate.ps1

# Then run all tests including integration tests
cargo test --all
```

## Adding New Tests

1. Create new test file in `tests/` directory
2. Import required modules from `rust_bridge`
3. Write test functions with `#[test]` attribute
4. Run with `cargo test`

Example:
```rust
use rust_bridge::types::*;

#[test]
fn test_new_feature() {
    // Your test here
    assert_eq!(1 + 1, 2);
}
```

## Test Dependencies

All test dependencies are defined in `Cargo.toml` under `[dev-dependencies]`:
- `tempfile` - For creating temporary test files
- `mockall` - For mocking (if needed)
- `criterion` - For performance benchmarking

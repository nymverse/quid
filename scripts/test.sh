#!/bin/bash
set -e

echo "Running QuID test suite..."

# Run all tests
cargo test --workspace

# Run clippy lints
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Test CLI
echo "Testing CLI..."
cargo run --bin quid -- create --security-level 1

echo "All tests passed!"
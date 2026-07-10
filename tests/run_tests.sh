#!/bin/bash
# Standalone Linux Test Execution Script for Nullsploit WAF Engine
# Runs core signature validation tests in userspace compatibility mode.

set -e

# Move to the tests directory
cd "$(dirname "$0")"

echo "[TESTING] Preparing testing environment..."
mkdir -p /etc/fw_inspect/yara

echo "[TESTING] Building test suite..."
make clean
make

echo "[TESTING] Running core logic validation tests..."
./test_runner

echo "[TESTING] Cleaning up build artifacts..."
make clean

echo "[TESTING] Core engine validation tests completed successfully!"

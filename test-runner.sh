#!/bin/bash
# this is for continuous test under multithreaded conditions.
export RUST_BACKTRACE=full
export TEST_MULTITHREADED=true

for i in {32..1}; do
    echo "Running tests with $i threads..."
    cargo test -- --test-threads=$i
    if [ $? -ne 0 ]; then
        echo "Tests failed with $i threads. Exiting."
        exit 1
    fi
done

echo "All tests passed for threads 1 to 32."

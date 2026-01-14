#!/usr/bin/env bash

OUTPUT_BASE="./output"

find .. -type f -name "*.md" | while read -r filepath; do
    # Get relative path from parent directory
    rel_path="${filepath#../}"
    rel_dir=$(dirname "$rel_path")
    filename=$(basename "$filepath")
    
    # Create output subdirectory if it doesn't exist
    output_dir="$OUTPUT_BASE/$rel_dir"
    mkdir -p "$output_dir"
    
    ./pandoc.sh "$filepath" "$output_dir/$filename.html"
done

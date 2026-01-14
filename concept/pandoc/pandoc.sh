#!/usr/bin/env bash

# Usage: ./pandoc.sh <input_file_path> <output_file_path>

INPUT_FILE="$1"
OUTPUT_FILE="$2"

# basic validation
if [[ -z "$INPUT_FILE" || -z "$OUTPUT_FILE" ]]; then
  echo "Usage: $0 <input_file_path> <output_file_path>"
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: Markdown file not found: $INPUT_FILE"
  exit 1
fi

# Get the directory of the input file for resource path
RESOURCE_DIR=$(dirname "$INPUT_FILE")
MD_FILE=$(basename "$INPUT_FILE")

# Ensure output directory exists
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR"

pandoc "$INPUT_FILE" \
  -o "$OUTPUT_FILE" \
  --embed-resources --standalone \
  --metadata title="$MD_FILE" \
  --katex=/home/quartus/.npm-global/lib/node_modules/katex/dist/ \
  --css=fullwidth.css \
  --resource-path="$RESOURCE_DIR" \
  --lua-filter="convert_links.lua"
  #--verbose

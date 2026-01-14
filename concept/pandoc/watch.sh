
#!/usr/bin/env bash

WATCH_DIR=".."
OUTPUT_BASE="./output"

inotifywait -m -r -e close_write --format '%w%f' "$WATCH_DIR" | while read -r filepath; do
  # only handle .md files
  [[ "$filepath" == *.md ]] || continue

  # make sure the file still exists (not deleted)
  [[ -f "$filepath" ]] || continue

  # Get relative path from WATCH_DIR
  rel_path="${filepath#$WATCH_DIR/}"
  rel_dir=$(dirname "$rel_path")
  filename=$(basename "$filepath")
  
  # Create output subdirectory if it doesn't exist
  output_dir="$OUTPUT_BASE/$rel_dir"
  mkdir -p "$output_dir"

  echo "$(date +'%H:%M:%S') Processing Markdown file: $rel_path"
  ./pandoc.sh "$filepath" "$output_dir/$filename.html"
done

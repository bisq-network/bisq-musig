#!/bin/bash
# This script automates the installation of pre-commit hooks
# Any contributor needs to run this before starting making contributions to the project.

cd .git/hooks
if [ ! -f pre-commit ]; then
    cat << 'EOF' > pre-commit
#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

ROOT=$(git rev-parse --show-toplevel)

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}PRE-COMMIT: jq is not installed. Please install jq to proceed.${RESET}"
    exit 1
fi

# Only require fixing warnings of modified files, so that preexisting code with warnings shouldn't stop us from committing.
# cargo clippy can't be applied to specific file so we run it and parse its output to get the files involved and compare them with modified git files

echo -e "${BLUE}PRE-COMMIT: Running cargo clippy --quiet${RESET}"

CLIPPY_OUTPUT=$(cargo clippy --quiet --message-format=json \
  | jq -r '.message.rendered? // empty')

GIT_DIFF_FILES=$(git diff --cached --name-only --diff-filter=ACM)
FILES_WITH_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -Ff <(echo "$GIT_DIFF_FILES") || true)

if [ -n "$FILES_WITH_WARNINGS" ]; then
  echo "$FILES_WITH_WARNINGS" | while IFS= read -r line; do
    if [[ "$line" == *"-->"* ]]; then
      file=$(echo "$line" | awk '{print $2}')
      echo -e "${YELLOW} Please fix warnings in file:${RESET} ${GREEN}$file${RESET}"
    else
      echo "$line"
    fi
  done
  exit 1
fi

# Run formatting, this runs only on modified files
# This requires nightly channel because --skip-children isn't a stable feature of rustfmt
# --skip-children is needed so that rustfmt doesn't recurse and update formatting of unmodified files

echo -e "${BLUE}PRE-COMMIT: Running cargo fmt${RESET}"

for file in $(git diff --cached --name-only --diff-filter=ACM | grep ".rs$"); do
  PATH_FILE="$ROOT/$file"
  $(rustfmt +nightly --unstable-features --skip-children --edition 2021 -- "$PATH_FILE")
  git add "$PATH_FILE"
done

# Insert new line at the end of modified files if none.

echo -e "${BLUE}PRE-COMMIT: Adding new line at the end ${RESET}"

for file in $GIT_DIFF_FILES; do
  if file "$file" | grep -q "text"; then
    if [ -s "$file" ] && [ -n "$(tail -c1 "$file")" ]; then
      echo >> "$file"
      git add $file
    fi
  fi
done

EOF
chmod +x pre-commit
fi

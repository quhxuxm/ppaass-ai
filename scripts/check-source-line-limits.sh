#!/bin/sh
set -eu

limit="${SOURCE_LINE_LIMIT:-400}"

violations="$(
    git ls-files --cached --others --exclude-standard |
    grep -E '\.(rs|ts|js|html)$' |
    while IFS= read -r source_file; do
        [ -f "$source_file" ] || continue
        line_count="$(awk 'END { print NR }' "$source_file")"
        if [ "$line_count" -gt "$limit" ]; then
            printf '%s:%s exceeds the %s-line source limit\n' \
                "$source_file" "$line_count" "$limit"
        fi
    done
)"

if [ -n "$violations" ]; then
    printf '%s\n' "$violations"
    exit 1
fi

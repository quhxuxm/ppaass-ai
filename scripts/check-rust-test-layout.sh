#!/bin/sh
set -eu

repository_files() {
    git ls-files --cached --others --exclude-standard
}

source_violations="$(
    repository_files |
    while IFS= read -r source_file; do
        case "$source_file" in
            src/*.rs | */src/*.rs) ;;
            *) continue ;;
        esac
        [ -f "$source_file" ] || continue

        case "$source_file" in
            src/*) source_relative="${source_file#src/}" ;;
            *) source_relative="${source_file#*/src/}" ;;
        esac
        source_basename="${source_relative##*/}"
        case "$source_basename" in
            test.rs | tests.rs)
                printf '%s:1:test-only Rust source filename\n' "$source_file"
                ;;
        esac
        case "/$source_relative/" in
            */test/* | */tests/*)
                printf '%s:1:test-only Rust source directory\n' "$source_file"
                ;;
        esac

        awk '
            function has_test_cfg(value) {
                return value ~ /(^|[,([:space:]])test([),[:space:]]|$)/
            }
            function report(line, detail) {
                printf "%d:%s\n", line, detail
            }
            {
                if (!in_cfg &&
                    $0 ~ /#[[:space:]]*\[[[:space:]]*cfg(_attr)?[[:space:]]*\(/) {
                    in_cfg = 1
                    cfg_line = NR
                    cfg_text = $0
                } else if (in_cfg) {
                    cfg_text = cfg_text " " $0
                }

                if (in_cfg && $0 ~ /\]/) {
                    if (has_test_cfg(cfg_text)) {
                        report(cfg_line, "test-only cfg attribute")
                    }
                    in_cfg = 0
                    cfg_text = ""
                }

                if ($0 ~ /#[[:space:]]*\[[[:space:]]*([[:alnum:]_]+::)*(test|bench|rstest|test_case|proptest)([[:space:](\]]|$)/) {
                    report(NR, "Rust test attribute")
                }
                if ($0 ~ /(^|[^[:alnum:]_])mod[[:space:]]+(test|tests)[[:space:]]*([;{]|$)/) {
                    report(NR, "Rust test module")
                }
            }
        ' "$source_file" |
            sed "s#^#$source_file:#"
    done
)"

bypass_violations="$(
    repository_files |
    while IFS= read -r test_file; do
        case "$test_file" in
            tests/*.rs | */tests/*.rs) ;;
            *) continue ;;
        esac
        [ -f "$test_file" ] || continue
        grep -nE \
            'include[[:space:]]*!|#[[:space:]]*\[[[:space:]]*path[[:space:]]*=|\.\.[/\\]+src' \
            "$test_file" |
            sed "s#^#$test_file:#" || true
    done
)"

if [ -n "$source_violations" ]; then
    echo "Rust test code must live in each crate's top-level tests/ directory:" >&2
    printf '%s\n' "$source_violations" >&2
    exit 1
fi

if [ -n "$bypass_violations" ]; then
    echo "Cargo integration tests must not include or path-import production src files:" >&2
    printf '%s\n' "$bypass_violations" >&2
    exit 1
fi

echo "Rust test layout checks passed"

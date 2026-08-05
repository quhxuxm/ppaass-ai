# Repository Engineering Rules

## Source file size

- Every source, test, script, and workflow file must contain no more than 400 physical lines.
- Treat 400 lines as a hard maximum, not a target. Split a file into cohesive modules before it reaches the limit.
- Do not satisfy the limit by minifying code, combining unrelated statements, or otherwise reducing readability.
- When adding code to a file near the limit, refactor or extract the relevant responsibility in the same change.
- Before handing off code changes, run `./scripts/check-source-line-limits.sh` from the repository root and fix every reported violation.
- Keep this quality check in development and test workflows. Deployment workflows must build and deploy without running code-style or source-line-limit checks.

## Rust test layout

- Put all Rust test code in the owning crate's top-level `tests/` directory, following Cargo integration-test conventions.
- Do not add `#[test]`, `#[bench]`, test-only `#[cfg(...)]`, or `mod test` / `mod tests` blocks under a crate's `src/` directory.
- Do not create `src/test.rs`, `src/tests.rs`, `src/test/`, or `src/tests/`.
- Tests must exercise production code through the crate's public API. Do not bypass this boundary with `include!`, `#[path = ...]`, or relative imports of files under `src/`.
- Before handing off Rust changes, run `./scripts/check-rust-test-layout.sh` and the relevant `cargo test` command from the repository root.

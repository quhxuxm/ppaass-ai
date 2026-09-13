# Repository Engineering Rules

## Documentation layout

- Keep human-facing Markdown documentation in `docs/`; `README.md` is the only
  human-facing documentation entry point at the repository root.
- Keep `AGENTS.md` at the repository root. It is an instruction file for coding
  agents, not product documentation.
- Put Mermaid source directly in the relevant Markdown document. Do not create
  standalone diagram files under `docs/diagrams/` unless a task explicitly needs
  a separately consumable diagram asset.
- When adding, moving, renaming, or deleting a document, update the navigation
  links in `README.md` and verify local Markdown links.

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

## Handoff checks

- For every change, run `git diff --check` before handoff.
- For source, test, script, or workflow changes, run
  `./scripts/check-source-line-limits.sh`; it also runs the Rust test-layout
  check.
- For Rust changes, run `cargo fmt` and the relevant locked `cargo test` command.
- For Proxy Entry or Registry deployment changes, run
  `bash ./scripts/test-proxy-deployment-layout.sh`.

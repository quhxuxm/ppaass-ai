# Copilot Instructions (Rust)

These instructions apply to all code changes in this repository. Follow them unless the user explicitly overrides them.

## 1) Rust toolchain & project assumptions
- Target Rust edition: **2024** (do not introduce 2018-era patterns).
- Prefer stable Rust; do not require nightly features unless explicitly requested.
- Use `cargo` for all build/test/format tasks.

## 2) Coding style & conventions
- Format with `rustfmt` (default settings) and keep diffs minimal.
- Prefer idiomatic Rust:
  - Use iterators over indexing when possible.
  - Avoid unnecessary `clone()`; prefer borrowing (`&T`, `&str`) and `Cow` when appropriate.
  - Use `Option`/`Result` instead of sentinel values.
  - Prefer `?` for error propagation.
- Naming:
  - Types: `UpperCamelCase`
  - Functions/vars/modules: `snake_case`
  - Constants: `SCREAMING_SNAKE_CASE`
- Public API:
  - Keep public interfaces small and well-documented.
  - Avoid breaking changes unless requested.

## 3) Error handling
- Do not use `unwrap()`/`expect()` in production code.
  - Allowed only in tests, examples, or when guarded by an invariant that is clearly explained in a comment.
- Use structured errors:
  - Prefer `thiserror` for library error types.
  - Prefer `anyhow` for application binaries (if the repo already uses it).
- Include context on errors (e.g., `.with_context(|| "...")`) when it materially improves debugging.

## 4) Safety rules
- Prefer safe Rust.
- `unsafe` is **forbidden** unless explicitly required; if used:
  - Keep the `unsafe` block as small as possible.
  - Add a comment describing the safety invariants and why they hold.
  - Add tests that exercise the unsafe code path.

## 5) Performance & allocations
- Avoid unnecessary allocations in hot paths.
- Prefer passing `&str` rather than `String` when you don’t need ownership.
- Use `Vec::with_capacity` when the size is known or can be bounded.
- Avoid quadratic behavior; call out complexity in comments when non-obvious.

## 6) Dependencies
- Do not add new crates unless necessary.
- Before adding a dependency, consider:
  - whether it already exists in the repo,
  - whether stdlib is sufficient,
  - compile time and MSRV implications.
- If you add a crate, explain why in the PR description / commit message.

## 7) Documentation
- Public items must have rustdoc comments (`///`) explaining:
  - what it does,
  - inputs/outputs,
  - error cases,
  - examples when helpful.
- Keep module-level docs in `mod.rs` or at the top of the module file.

## 8) Testing requirements
- Any bug fix must include a regression test.
- Any new feature must include tests that cover:
  - happy path,
  - boundary cases,
  - error cases.
- Prefer `#[test]` unit tests close to the code.
- Use integration tests (`tests/`) for end-to-end behavior.

## 9) Common commands (run before finalizing changes)
- `cargo fmt`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`

## 10) When requirements are unclear
Before implementing, ask concise clarifying questions about:
- expected behavior (inputs/outputs),
- error handling expectations,
- performance constraints,
- MSRV / platform requirements,
- whether to preserve backward compatibility.

## 11) Output expectations for Copilot Chat
When proposing changes:
- Provide a short plan first.
- Identify files to change and why.
- If suggesting code, keep it minimal, compile-ready, and consistent with repository patterns.
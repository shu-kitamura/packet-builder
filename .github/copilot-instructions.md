# Copilot Development Guidelines (packet-builder)

These are mandatory rules for using GitHub Copilot (and similar code-generation tools) to create or edit code in this repository. Changes that do not meet these rules will be rejected.

## Minimum mandatory requirements

1) Implement according to the RFCs
- Follow the RFCs located under `docs/rfc/`

2) Zero warnings from formatting and static analysis
- All changes MUST pass formatting and static analysis with no warnings.
- Commands (same bar as CI):
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`

3) Add tests for new implementations
- When adding new features, types, or public APIs, include unit tests and/or doc tests.
- For serialization/deserialization and checksum calculations, cover the happy path plus 1–2 boundary/edge cases.

4) All tests must pass
- After your changes, the following must succeed locally:
  - `cargo test --all`

5) Preserve `#![no_std]`
- This repository uses `#![no_std]`. Do not introduce a dependency on `std`. Use `core`/`alloc` as needed.
- Do not submit changes that break `no_std`. Confirm the code compiles in tests.

## Implementation guide (example: TCP / RFC 9293)
- Implement header format, flags, and options (at minimum EOL/NOP/MSS) as defined by RFC 9293.
- Compute checksums using 16-bit one's complement including the IPv4/IPv6 pseudo header.
- Follow IANA flag assignments (CWR/ECE/URG/ACK/PSH/RST/SYN/FIN) per RFC 9293 Section 6.
- Support urgent semantics for compatibility, but document that new use is discouraged (see RFC 6093 for background).

## Coding conventions
- Use network byte order (big-endian) for encoding/decoding.
- Public APIs MUST include documentation comments (`///`) referencing the governing RFC and section number.
- Minimize new dependencies and document the rationale and benefits in PRs.
- Minimize `unsafe`; when necessary, explain the reason and invariants in comments.

## PR checklist (verify before submitting)
- [ ] Implemented with references to the relevant RFC and section(s) under `docs/rfc/` (stated in the PR description).
- [ ] `cargo fmt --all -- --check` succeeds.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` succeeds.
- [ ] Added tests for new functionality (happy path + at least 1–2 boundary/edge cases).
- [ ] `cargo test --all` succeeds.
- [ ] `#![no_std]` preserved (no `std` dependency).

## Common commands
```bash
# Formatting (verify no diffs)
cargo fmt --all -- --check

# Clippy (treat warnings as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Build & test
cargo build --all-targets
cargo test --all
```

## Documentation
- Provide at least one usage example (doctest) for any new public API.
- Where specification choices are unclear, include a brief citation (summary) and section number from the relevant RFC in comments.

---
This file serves as a quality gate for AI-assisted code generation in this repository. Changes that do not adhere to it will generally be rejected.
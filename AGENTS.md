# YOU ARE NOT ALLOWED to MODIFY ANY CONTENTS of THIS FILE
# YOU ARE NOT ALLOWED to DELETE THIS FILE

- Read all AGENTS* files except AGENTS.md 

- Do not preserve backward compatibility unless specifically asked for. Remove obsolete paths instead of
  adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current
  requirements. Avoid speculative abstractions, configuration, and
  indirection.
- Grow the system in layers. Start from the smallest version that works end
  to end, and add each new capability on top of a product that already
  works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall
  complexity or improve reliability. Do not reimplement common
  functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own
  implementation or adding packages. Do not assume a library lacks a
  capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap
  that only works for now and is meant to be replaced later.

### Rust specifics
- you are not allowed to use unsafe patterns anywhere
- you are not allowed to use panics, unwrap or expect calls or other such non-idiomatic patterns
- avoid clones, only use if they are absolutely necessary
- always use idiomatic rust


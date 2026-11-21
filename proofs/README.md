# proofs

Lean 4 project that will hold the formal verification of baldssl.

Status: compile-only skeleton. CI builds it against the pinned Aeneas Lean
library to keep the toolchain working; there is no extracted code and there are
no theorems yet (tracked in `../TODO.md`).

- Lean: `lean-toolchain` (must equal Aeneas' `backends/lean/lean-toolchain` at
  the pinned `rev` in `lakefile.toml`).
- Build: `make lean` (runs `lake exe cache get && lake build`; the Mathlib cache
  avoids compiling Mathlib).

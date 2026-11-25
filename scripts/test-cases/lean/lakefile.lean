import Lake
open Lake DSL

-- Validation cases for the rh-check scanners. Pinned to the setup that produced the
-- scanned export: Lean 4.33.1, lean4export tag v4.33.0
-- (commit 15f6055e299ad5b89345e533cc2192f4cc00f659).
package «rhcheck-cases»

require lean4export from git
  "https://github.com/leanprover/lean4export" @ "v4.33.0"

@[default_target]
lean_lib Cases

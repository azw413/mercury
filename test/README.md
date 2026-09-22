# Bytecode fixtures and verification

`box2d.hbc` is the committed version-96 fixture used by the semantic editing
milestone. The default CLI integration test decodes all 983 functions, rebuilds
and decodes the file, checks the semantic text, edits a string and loop bound,
and checks deterministic output. No sibling repositories or runtime executable
are needed for this test.

Run the self-contained suite:

```sh
cargo test --workspace
```

Run the execution check with a Hermes executable that reports
`HBC bytecode version: 96` in `-version`:

```sh
HERMES_BIN=/absolute/path/to/hermes \
  cargo test -p mercury-cli --test box2d_roundtrip -- --ignored
```

This check executes the original and unchanged rebuild and requires identical
stdout (`Completed step 0` through `Completed step 19`). It then changes the
message to `Edited step ` and the loop limit to 3, rebuilds, and requires exactly
three edited output lines. A missing or incompatible runtime fails the explicitly
requested check; it is not silently skipped.

The runtime used to verify this milestone reports Hermes release `0.12.0`,
HBC version `96`, and has SHA-256
`7321943526c4142a0c1d688de72d9292dd3f98ebbfbd8955d85896b1c766325a`.
The HBC version, rather than the release label alone, determines compatibility.

Three legacy parser checks use `hermes-dec/tests/sample.hbc` (version 94), and
one spec comparison uses the same external checkout. They are explicit opt-in
checks, configured with `HERMES_DEC_ROOT`. To run every check, including runtime
execution and external comparisons:

```sh
HERMES_BIN=/absolute/path/to/hermes \
HERMES_DEC_ROOT=/absolute/path/to/hermes-dec \
  cargo test --workspace -- --include-ignored
```

The external checks were verified against hermes-dec commit
`04f1a69a733135a9da632030c2403ea36a44387e`.

`amazon.hbc` provides a larger container-parsing fixture. `hex.hbc` now covers
compact version-96 header parsing and byte-equal header writing; the small-file
layout detection bug was fixed during SWC integration. The former `/tmp/hex.semantic.current.txt` dependency has
been replaced by the committed Box2D CLI round-trip test and focused assembler
regressions.

The SWC module adds self-contained source/AST and bytecode tests plus optional
execution tests requiring both `HERMESC_BIN` and `HERMES_BIN`. See
[the module instructions](../crates/swc/README.md). Set all three toolchain
variables when running the full workspace with `--include-ignored`.

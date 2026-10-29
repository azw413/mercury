# Hermes regex compiler

The `mercury_hbc::regex` module compiles a RegExp pattern and flags into the
regex bytecode that HBC 96 stores for `CreateRegExp`. The Hermes VM never
compiles a literal's pattern itself; it runs the bytecode from the module's
regexp table, so a native compiler has to produce exactly what hermesc would.

This is a port of the compiler half of Hermes's `lib/Regex` (parser, syntax
tree, emitter) and the parts of `lib/Platform/Unicode` it uses, from the
`rn/0.73-stable`..`rn/0.76-stable` branches, which all ship HBC 96 and share one
regex bytecode format. It keeps Hermes's quirks where they change the output,
such as the optimizer skipping the node after a merged character run, and
complementing each pool of an inverted `\P{...}` separately inside brackets.

`compile` returns the bytecode and the named groups. Group names aren't in
the bytecode: hermesc passes them in a separate `initRegexNamedGroups` call.
Errors carry Hermes's messages.

## Unicode data

`src/regex/unicode_data.rs` is generated from Hermes's `UnicodeData.inc`
(Unicode 15.1 for these branches) so case folding, identifier classes and
`\p{...}` match hermesc exactly. From the workspace root, regenerate it with:

```
python3 tools/gen_unicode_data.py path/to/hermes/lib/Platform/Unicode/UnicodeData.inc crates/swc/src/regex/unicode_data.rs
```

## Verification

`tests/fixtures/hermesc.jsonl` records what an HBC 96 hermesc does with about
2,000 patterns: hand-picked cases covering every construct and Annex B corner,
plus deterministic random and grammar-generated ones. Each entry is either the
bytecode (hashed when long) or the error message. Run the differential test with:

```
cargo test -p mercury-hbc --test regex_hermesc_oracle
```

To regenerate the fixture:

```
HERMESC_BIN=/path/to/hermesc cargo test -p mercury-hbc --test regex_hermesc_oracle -- --ignored regenerate
```

## Licence

Hermes is MIT licensed (`LICENSE-hermes`); its regex engine derives from libc++
(`LICENSE-libcxx`).

# mercury

`mercury` is a Rust command-line toolkit for Hermes bytecode reverse engineering, disassembly, reassembly, and transformation.

The core design rule is that Hermes bytecode versions must be handled through generated versioned specs rather than scattered ad hoc parser branches.

## CLI Usage

Show embedded supported bytecode versions:

```bash
cargo run -p mercury-cli -- versions
```

Decode a Hermes bytecode file in raw form:

```bash
cargo run -p mercury-cli -- decode test/hex.hbc
```

Decode to the normalized semantic view:

```bash
cargo run -p mercury-cli -- decode test/hex.hbc --format semantic
```

Assemble semantic text back into a real `hbc96` file:

```bash
cargo run -p mercury-cli -- assemble /tmp/hex.semantic.txt --target-version 96 -o /tmp/hex.assembled.hbc
```

Write decode output to a file:

```bash
cargo run -p mercury-cli -- decode test/amazon.hbc --format semantic -o /tmp/amazon.semantic.txt
```

Extract a versioned spec from the local Hermes checkout:

```bash
cargo run -p mercury-cli -- extract-spec --tag v0.12.0
```

Extract a spec and compare it against `hermes-dec`:

```bash
cargo run -p mercury-cli -- extract-spec --tag v0.12.0 --compare-hermes-dec ../hermes-dec
```

## Current Status

Implemented now:

- versioned spec extraction from `../hermes`
- generated JSON specs keyed by Hermes bytecode version under `spec/generated/`
- embedded build-time spec registry for the CLI
- binary parsing for real `.hbc` files including:
  - file header
  - section boundaries
  - compact and overflowed function headers
  - function bodies
  - function info
  - exception and debug-offset records
  - string tables and storage
  - CJS and function-source pair tables
- spec-backed instruction decoding
- raw IR generation
- semantic IR lowering
- raw and semantic CLI decode modes
- first semantic assembly parser and raiser
- first real `assemble -o out.hbc` path for semantic `hbc96` modules
- minimal `hbc96` container writer with:
  - generated string tables
  - generated identifier hashes
  - synthesized small function headers
  - empty debug section
  - SHA-1 footer

Working fixtures:

- `test/hex.hbc`
- `test/amazon.hbc`
- `../hermes-dec/tests/sample.hbc`

Current semantic status:

- `hex.hbc` lowers almost entirely into structured semantic ops
- `amazon.hbc` lowers end to end in semantic mode
- the current semantic decode output for `hex.hbc` can now be parsed, raised, and reassembled into a valid `hbc96` file that Hermes itself will disassemble successfully
- the previous fallback-heavy lowering surface has been reduced to the point that the next major task is expanding assembler coverage and stabilizing the semantic text grammar, not chasing broad missing instruction families

Not implemented yet:

- byte-perfect full-file rewrite path
- full semantic-to-raw raising coverage for the entire semantic vocabulary
- container writing beyond the current minimal `hbc96` path
- exact/preservation-oriented rebuild mode

## Semantic Assembly Draft

The semantic text format is now the primary assembly target.

Guiding rules:

- function labels are authoritative, not instruction offsets
- string literals are authored as literals, not raw string ids
- function references are symbolic, using `@name`
- semantic readability takes priority over byte-preserving container details

Current parser shape accepted by `crates/asm`:

```text
bytecode_version 96

.strings
  s0 = ""
  s9 = "encode"
.end

.function @global params=1 frame=3 env=0
  declare_global_var "encode"
  create_environment r0
  create_closure r2, r0, @encode
L1:
  branch_false r10, L2
.end

.function @encode params=2 frame=25 env=0
  load_param r9, 1
  return r0
.end
```

Notes:

- instruction offsets like `0000:` are currently accepted for compatibility with the existing disassembler output, but they are intended to become display-only rather than required syntax
- `.strings` is also currently accepted in the emitted form `s9 = "encode"`, but the longer-term intent is that string literals in instructions are the semantic source of truth and the assembler will rebuild string tables automatically

## Goals

- Extract canonical Hermes bytecode metadata directly from upstream Hermes source and tags.
- Represent opcode definitions and container-format definitions in a versioned intermediate format.
- Parse Hermes bytecode files into a byte-exact raw model suitable for round-trip rewriting.
- Provide a stable semantic IR for reverse engineering, rewriting, and obfuscation.
- Disassemble into a deterministic text format and assemble back into byte-for-byte equivalent binaries when unchanged.

## Major Components

### `mercury-cli`

User-facing command-line entry point.

Current commands:

- `versions`
- `decode`
- `assemble`
- `extract-spec`

### `mercury-spec-extract`

Reads Hermes source from `../hermes` and emits canonical versioned specs.

It extracts both:

- bytecode metadata:
  - `BytecodeVersion.h`
  - `BytecodeList.def`
  - operand meanings
  - builtins
- container metadata:
  - `BytecodeFileFormat.h`
  - function header layouts
  - bitfields
  - section order and alignment
  - serializer-derived container semantics

### `mercury-spec`

Defines the versioned independent spec format used by the rest of the project.

This is the compatibility boundary between upstream Hermes and Mercury.

### `mercury-spec-builtin`

Embeds generated `hbcNN.json` specs into the final binary at build time.

This makes the CLI self-contained and lets the binary report exactly which Hermes bytecode versions it supports.

### `mercury-binary`

Owns parsing and writing `.hbc` files using `mercury-spec`.

The crate is split by domain:

- `header.rs`
- `sections.rs`
- `functions.rs`
- `tables.rs`
- `decode.rs`
- `encode.rs`
- `parse.rs`

Function-domain and table-domain parsing/writing are kept paired for symmetry and future round-tripping.

### `mercury-ir`

Defines the internal representations above the raw binary layer.

Current split:

- `Raw`
  - exact decoded structures suitable for lossless rewriting
- `Semantic`
  - normalized instruction layer used by the semantic decode mode

### `mercury-disasm`

Planned home for deterministic text disassembly.

At the moment, the semantic decode formatter in `mercury-cli` is acting as the proving ground for that eventual assembly syntax.

### `mercury-asm`

Home for parsing Mercury assembly text, raising it into raw bytecode instructions, and feeding binary emission through `mercury-binary`.

Current status:

- semantic assembly AST
- line-oriented parser for the current semantic disassembly syntax
- first semantic-to-raw raiser for a useful `hbc96` subset
- first end-to-end semantic assembly path that can emit a real `.hbc` through the CLI
- support for:
  - `.strings`
  - `.function`
  - labels
  - optional displayed instruction offsets
  - registers, labels, function refs, string literals, integers, and barewords as operands

The eventual target is:

- `decode -> encode -> identical bytes` when unchanged
- semantic editing and obfuscation against a stable IR

## Current Version Support

The build currently embeds generated specs for the versions present in `spec/generated/`.

At the time of writing this README, that includes:

- `hbc89`
- `hbc94`
- `hbc96`

## Near-Term Plan

The next major implementation step should be to turn the current semantic decode output into a real assembler target:

1. freeze the semantic text grammar
2. remove instruction offsets from required semantic syntax
3. define semantic-to-raw raising against a target bytecode version
4. begin binary emission from `mercury-asm`
5. add semantic round-trip tests for `decode -> parse -> raise`

# mercury

`mercury` is a Rust command-line toolkit for Hermes bytecode reverse engineering, disassembly, reassembly, and transformation.

Mercury is dual-licensed under [GPLv3](LICENSE) or the alternative
[commercial license](LICENSE-commercial). Cargo metadata identifies the GPLv3
option as `GPL-3.0-only`. Commercial terms and eligibility, including the
existing employer exemption, are described in `LICENSE-commercial`.

The core design rule is that Hermes bytecode versions must be handled through generated versioned specs rather than scattered ad hoc parser branches.

## CLI Usage

Show embedded supported bytecode versions:

```bash
cargo run -p mercury-cli -- versions
```

Decode a Hermes bytecode file in raw form:

```bash
cargo run -p mercury-cli -- decode test/box2d.hbc
```

Decode to the normalized semantic view:

```bash
cargo run -p mercury-cli -- decode test/box2d.hbc --format semantic -o /tmp/box2d.semantic.txt
```

Assemble semantic text back into a real `hbc96` file:

```bash
cargo run -p mercury-cli -- assemble /tmp/box2d.semantic.txt --target-version 96 -o /tmp/box2d.assembled.hbc
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

Verified fixtures:

- `test/box2d.hbc`: version-96 semantic decode, rebuild, edit, and Hermes execution
- `test/amazon.hbc`: large-container parsing
- `hermes-dec/tests/sample.hbc`: version-94 parsing in explicitly configured external tests

The version-96 editing milestone now includes:

- deterministic semantic text with symbolic labels and no required instruction offsets
- checked operand widths and counts, duplicate-symbol rejection, and recalculated long branches
- preservation of function names, JSON string escapes, and negative zero
- correct SHA-1 footers calculated after writing the final header
- explicit assembly rejection of unsupported runtime metadata and cross-version rebuilds
- a self-contained Box2D editing test and an opt-in Hermes execution test that verifies a deliberate edit

`test/hex.hbc` now covers compact version-96 header parsing and header
byte-equality after the SWC integration exposed and fixed the small-file layout
heuristic. Box2D remains the verified semantic editing fixture.

See [fixture and test instructions](test/README.md) for reproducible checks.

Not implemented yet:

- byte-perfect full-file rewrite path
- full semantic-to-raw raising coverage for the entire semantic vocabulary
- container writing beyond the current minimal `hbc96` path
- exact/preservation-oriented rebuild mode

## JavaScript / TypeScript and SWC

The new [`mercury-swc`](crates/swc/README.md) module parses JS/TS into actual SWC
AST structs, prints/transforms them, compiles scripts through a configured
version-96 `hermesc`, and decompiles a deliberately limited bytecode subset into
executable SWC trees. The first decompiler uses register temporaries and a
basic-block dispatcher. It reconstructs mutable captured environments, including
siblings and multiple lexical levels, and preserves empty and sparse array
allocation. Exception handlers remain unsupported.

```sh
cargo run -p mercury-cli -- compile crates/swc/tests/fixtures/control_flow.js --hermesc /path/to/hermesc -o /tmp/example.hbc
cargo run -p mercury-cli -- decompile /tmp/example.hbc -o /tmp/example.js
```

See the module README for the supported contract, Rust interface, and execution
tests, including an SWC visitor edit verified in Hermes.

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

- instruction offsets like `0000:` are accepted for compatibility and ignored during encoding; labels determine branch targets, and the assembler currently uses long branches
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
  - decoded instructions preserving their original encoding; full-container preservation is still pending
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

## Semantic rebuild contract and next steps

The current writer supports a subset of version 96. It rebuilds a minimal
container and drops debug/source metadata; it does not promise byte-for-byte
preservation of the original file. Opaque literal/object buffers and their
string-table ordering are carried through unchanged. Editing those buffers or
reordering/removing their string entries is outside the verified editing path.

Decode remains available for inspection when rebuilding is unsupported. It
emits `.unsupported` markers for runtime metadata the writer cannot preserve
(such as exception handlers, strict/invocation flags, non-default options,
nonzero entry functions, and regexp/bigint tables). Assembly rejects those
markers with a reason. Unsupported instructions and values that do not fit the
selected encoding also fail explicitly. Long branches can make functions
larger; functions exceeding small-header limits are rejected.

The next steps are to move text formatting into `mercury-disasm`, expand
explicitly tested runtime metadata and instruction coverage, and model
container layout variants in the generated specs. Exact container preservation
needs a separate representation and byte-equality test contract.

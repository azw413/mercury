# mercury

`mercury` is a Rust command-line toolkit for Hermes bytecode reverse engineering, disassembly, reassembly, and transformation.

The project is designed around one non-negotiable requirement: support multiple Hermes bytecode versions simultaneously without scattering version-specific logic throughout the parser and assembler.

## Goals

- Extract canonical Hermes bytecode metadata directly from the upstream Hermes source tree and its git tags.
- Represent both opcode definitions and container-format definitions in a versioned, tool-friendly intermediate format.
- Parse Hermes bytecode files into a byte-exact raw model suitable for round-trip rewriting.
- Provide a higher-level editable assembly IR for reverse engineering, rewriting, and obfuscation.
- Disassemble into a stable text format and assemble back into byte-for-byte equivalent binaries when unchanged.

## Major Components

### `mercury-spec-extract`

Reads Hermes source from `../hermes` and emits canonical versioned specs.

This extractor has two distinct responsibilities:

- Bytecode spec extraction:
  - `BytecodeVersion.h`
  - `BytecodeList.def`
  - builtins and operand annotations
- Container format extraction:
  - `BytecodeFileFormat.h`
  - function header layout
  - file header evolution
  - section ordering, alignment, and related serialization metadata

The output of this phase will be checked-in generated data under `spec/generated/`.

### `mercury-spec`

Defines the versioned independent format used by the rest of the project.

This crate is the compatibility boundary between upstream Hermes source and Mercury’s parser, disassembler, and assembler. It should be data-driven and version-aware, not a pile of ad hoc per-version parser branches.

### `mercury-binary`

Owns parsing and writing `.hbc` files using `mercury-spec`.

This layer should preserve exact bytes, offsets, padding, and section boundaries. It is the foundation for byte-perfect round-tripping.

### `mercury-ir`

Defines stable internal representations above the raw binary layer.

Planned split:

- `Raw`:
  exact decoded structures suitable for lossless rewriting
- `Asm`:
  editable instruction-oriented IR with labels and symbolic references

### `mercury-disasm`

Converts parsed bytecode into a deterministic text format.

The initial priority is losslessness and stability, not pretty output.

### `mercury-asm`

Parses Mercury assembly text and emits binary output through `mercury-binary`.

The first target is `disassemble -> assemble -> identical bytes` for unchanged files.

### `mercury-cli`

User-facing command-line entry point.

Planned commands:

- `extract-spec`
- `inspect-spec`
- `parse`
- `disasm`
- `asm`

## Planned Milestones

1. Create the Rust workspace and crate boundaries.
2. Implement Hermes-source extraction for opcode and container metadata.
3. Define the independent versioned spec format.
4. Parse real `.hbc` containers for a narrow version set.
5. Round-trip write unchanged files byte-for-byte.
6. Add textual disassembly and reassembly.
7. Add editing and obfuscation-oriented transforms.

## Initial Extractor Scope

The extractor should start narrow and reproducible.

### Bytecode Spec

- enumerate supported Hermes tags
- read `BytecodeVersion.h`
- parse `BytecodeList.def`
- capture:
  - opcode ordering
  - operand types
  - operand semantic annotations
  - long jump variants
  - return-target markers
  - value-buffer user annotations

### Container Format

- read `BytecodeFileFormat.h`
- capture:
  - file magic and delta magic
  - file header fields by version
  - function header field layout
  - known small/overflowed header behavior
  - section ordering and alignment assumptions

The extractor should produce a single merged spec per bytecode version that contains both the instruction set and the container-format schema.

## Near-Term Plan

The next implementation pass should focus on `mercury-spec-extract`:

1. discover Hermes tags from the local clone
2. read selected files at each tag
3. parse opcode metadata into Rust structs
4. parse a first cut of container metadata into Rust structs
5. write canonical JSON snapshots for inspection and later parser use

## Current CLI

```bash
cargo run -p mercury-cli -- extract-spec --tag v0.12.0
cargo run -p mercury-cli -- extract-spec --tag v0.12.0 --compare-hermes-dec ../hermes-dec
```

Generated specs are keyed by Hermes bytecode version, for example `spec/generated/hbc89.json`, while still retaining the source git tag inside the JSON.

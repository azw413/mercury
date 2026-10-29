# Mercury

Mercury is a Rust library and command-line toolkit for compiling, inspecting,
transforming, and decompiling [Hermes](https://github.com/facebook/hermes)
bytecode. Its high-level API uses real [SWC](https://swc.rs/) syntax trees, and
its native compiler emits HBC 96 directly without invoking `hermesc`.

The workspace also provides versioned bytecode specifications, raw and semantic
IRs, semantic assembly, and a Hermes-compatible regular-expression compiler.

## Highlights

- Parse, print, and transform JavaScript or TypeScript with SWC.
- Compile supported JS/TS scripts to HBC 96 with no external compiler.
- Decompile HBC 96 into editable, executable SWC trees.
- Decode raw HBC 89, HBC 94, and HBC 96 containers using generated specs.
- Inspect normalized semantic IR and assemble the supported HBC 96 subset.
- Compile regular-expression literals to Hermes-compatible regex bytecode.

Mercury is dual-licensed under [GPLv3](LICENSE) or an alternative
[commercial license](LICENSE-commercial). Cargo metadata identifies the GPLv3
option as `GPL-3.0-only`; see the commercial license for its terms and employer
exemption.

## Library quickstart

Add the high-level crate:

```sh
cargo add mercury-hbc
```

Compile TypeScript and decompile the resulting bytecode entirely in memory:

```rust
use mercury_hbc::{decompile, HbcCompiler, SourceKind, SourceLanguage, SwcModule};

fn main() -> Result<(), mercury_hbc::Error> {
    let module = SwcModule::parse(
        "example.ts",
        "const answer: number = 40 + 2; print(answer);",
        SourceLanguage::TypeScript,
        SourceKind::Script,
    )?;

    let bytecode = HbcCompiler::new(96).compile(&module)?;
    let recovered = decompile(&bytecode)?;
    println!("{}", recovered.print());
    Ok(())
}
```

`HbcCompiler` does not require a Hermes installation and never executes the
input program. TypeScript is transpiled, not type-checked. Native compilation
currently targets scripts; ES modules must be bundled before compilation.

See the [`mercury-hbc` crate guide](crates/swc/README.md) for the complete API,
language contract, decompiler assumptions, and examples.

## Cargo examples

Run the in-memory quickstart from the workspace root:

```sh
cargo run -p mercury-hbc --example quickstart
```

Compile a JavaScript or TypeScript file without `hermesc`:

```sh
cargo run -p mercury-hbc --example compile -- input.js output.hbc
```

Decompile HBC 96 to JavaScript, writing to stdout or a file:

```sh
cargo run -p mercury-hbc --example decompile -- input.hbc output.js
```

Decompile, apply an SWC visitor, and rebuild in memory:

```sh
cargo run -p mercury-hbc --example roundtrip -- \
  test/box2d.hbc /tmp/box2d-rebuilt.hbc --rename-generated
```

## Command-line interface

From a checkout, invoke the CLI through Cargo:

```sh
cargo run -p mercury-cli -- --help
```

Compile and decompile:

```sh
cargo run -p mercury-cli -- compile input.js -o /tmp/example.hbc
cargo run -p mercury-cli -- decompile /tmp/example.hbc -o /tmp/recovered.js
```

List embedded bytecode versions and decode a file:

```sh
cargo run -p mercury-cli -- versions
cargo run -p mercury-cli -- decode test/box2d.hbc -o /tmp/box2d.raw.txt
cargo run -p mercury-cli -- decode test/box2d.hbc \
  --format semantic -o /tmp/box2d.semantic.txt
```

Assemble supported semantic HBC 96 text:

```sh
cargo run -p mercury-cli -- assemble /tmp/box2d.semantic.txt \
  --target-version 96 -o /tmp/box2d.assembled.hbc
```

The semantic assembler rebuilds a minimal container. It does not promise
byte-for-byte preservation of the original file, and rejects metadata and
instructions outside its explicit rebuilding contract.

## Compatibility at a glance

| Operation | Current support | Important boundary |
| --- | --- | --- |
| JS/TS parsing and printing | SWC scripts and modules | No type checking, JSX/TSX setup, or bundling |
| Native source compilation | HBC 96 scripts | Unsupported syntax returns an explicit error |
| Bytecode decompilation | HBC 96 | Executable reconstruction, not original source recovery |
| Raw container decoding | HBC 89, 94, and 96 | Support depends on the embedded versioned spec |
| Semantic assembly | HBC 96 subset | Minimal writer; not a byte-perfect roundtrip |
| Regex bytecode compilation | HBC 96 format | Matches the tested Hermes compiler format |

A bytecode version appearing in `versions` does not imply that every high-level
operation supports that version. Native source compilation and decompilation
currently have separate HBC 96 contracts.

## Native compiler coverage

The native compiler supports ordinary declarations and functions, closures and
captured mutation, lexical bindings and TDZ checks, arrow functions, parameters
and destructuring, arrays and objects, regular expressions, template literals,
fixed and spread calls, constructors, property operations, iteration,
short-circuiting, exceptions, and structured control flow. It emits real HBC
function and exception tables and preserves strictness, receivers, and iterator
cleanup.

The principal unsupported source constructs include destructuring assignments,
block-level function declarations, source-authored async and generator
functions, classes, unbundled modules, labeled control flow, and `for await…of`.
The decompiler can reconstruct bytecode for some constructs that the native
source compiler does not yet accept directly; coverage in one direction does not
imply coverage in the other.

## Decompiler output

Decompilation constructs SWC nodes directly from decoded instructions and a
private control-flow graph. It retains register temporaries and uses a
basic-block dispatcher rather than attempting to recover the author's original
control flow. Generated adapters preserve captured environments, exceptions,
iterators, generator and async suspension, constructors, class helper calls,
regular expressions, BigInts, and UTF-16 edge cases within the documented HBC 96
contract.

Original comments, formatting, local names, TypeScript types, and byte-identical
recompilation cannot be recovered from bytecode. Generated code assumes standard
intrinsics; arbitrary host interception and mutated globals are outside the
current contract.

## Workspace crates

| Crate | Role |
| --- | --- |
| `mercury-hbc` | Public SWC API, native HBC compiler, and HBC decompiler |
| `mercury-cli` | User-facing command-line interface |
| `mercury-binary` | Version-aware HBC parsing, instruction encoding, and container writing |
| `mercury-ir` | Raw and normalized semantic intermediate representations |
| `mercury-asm` | Semantic assembly parser and raiser |
| `mercury-regex` | Hermes-compatible regular-expression bytecode compiler |
| `mercury-spec` | Serializable versioned specification schema |
| `mercury-spec-builtin` | Embedded generated specification registry |
| `mercury-spec-extract` | Specification extraction from a Hermes checkout |
| `mercury-disasm` | Placeholder for future standalone disassembly helpers |

The central design rule is to handle bytecode versions through generated,
versioned specs rather than scattered ad hoc parser branches. Raw decoding keeps
encoding details; semantic lowering is a separate, normalized layer.

## Building and testing

The default test suite is self-contained:

```sh
cargo test --workspace
```

Validate the public documentation and examples:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc -p mercury-hbc --no-deps
cargo test --doc -p mercury-hbc
cargo check -p mercury-hbc --examples
```

Runtime and external-oracle tests are opt-in. They use `HERMES_BIN`,
`HERMESC_BIN`, and, for legacy comparisons, `HERMES_DEC_ROOT`. The corpus harness
runs 122 combinations of committed JavaScript programs and Hermes optimization
modes, comparing execution before and after HBC-to-SWC-to-HBC reconstruction.
See [fixture and test instructions](test/README.md) for reproducible commands.

## Regenerating bytecode specs

With a local Hermes checkout:

```sh
cargo run -p mercury-cli -- extract-spec \
  --hermes-repo /path/to/hermes --tag v0.12.0
```

Generated JSON specifications live under `spec/generated/` and are embedded by
`mercury-spec-builtin` at build time. After regenerating them, update the
package-local mirror used by crates.io builds:

```sh
cp spec/generated/*.json crates/spec-builtin/spec/generated/
cargo test -p mercury-spec-builtin
```

The sync test keeps the workspace and packaged registries identical. The current
registry contains HBC 89, 94, and 96.

# mercury-hbc

`mercury-hbc` is Mercury's high-level Rust API for JavaScript and TypeScript
source editing, native Hermes bytecode compilation, and executable HBC 96
decompilation. It exposes real [SWC](https://swc.rs/) ASTs and re-exports the
matching SWC dependency family for visitors and transformations.

The native [`HbcCompiler`](https://docs.rs/mercury-hbc/latest/mercury_hbc/struct.HbcCompiler.html)
emits HBC directly. It does not invoke `hermesc`, require a Hermes installation,
or execute the input program.

## Installation

```sh
cargo add mercury-hbc
```

For a checkout of Mercury, use a path dependency:

```toml
[dependencies]
mercury-hbc = { path = "/path/to/mercury/crates/swc" }
```

## Quickstart

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

TypeScript annotations and runtime constructs are lowered on a copy of the tree.
This is transpilation, not type checking or module bundling.

## API overview

### `SwcModule`

`SwcModule::parse(name, text, language, kind)` parses JavaScript or TypeScript as
a script or ES module. Fatal and recoverable parser diagnostics include the
supplied filename, line, and column. Parsing runs SWC's resolver and retains
comments and source locations.

- `program`, `comments`, and `source_map` expose the underlying SWC data.
- `with_ast` runs an editing or inspection closure with the module's SWC globals
  installed.
- `transform` applies an SWC pass in that same context.
- `print()` emits the current tree with comments and retains TypeScript syntax.
- `javascript()` lowers TypeScript on a copy and emits JavaScript without
  modifying the module.

Use the crate's `ast`, `visit`, and `swc_core` re-exports when writing visitors.
SWC interfaces are version-sensitive, and new bindings need fresh or deliberately
preserved syntax contexts. Exporting generated source-map files is not currently
implemented.

### `HbcCompiler`

`HbcCompiler::new(96).compile(&module)` lowers a script directly into a complete
HBC file. Other target versions and unbundled ES modules return
`Error::Unsupported`; unsupported source syntax is never silently delegated to an
external compiler.

### `decompile`

`decompile(&bytes)` accepts supported HBC 96 and constructs an executable SWC
module directly from Mercury's decoded IR and control-flow graph. It does not
generate text and parse that text back into an AST. The returned module can be
printed, edited, or compiled again.

### `HermesCompiler`

`HermesCompiler` is an optional compatibility adapter for an explicitly configured
`hermesc` executable. It is separate from the native compiler and is primarily
useful for external-oracle testing or syntax outside Mercury's native source
coverage.

### Lower-level modules

The same crate exposes `binary` for HBC parsing and writing, `ir` for raw and
semantic representations, `asm` for semantic assembly, `regex` for Hermes regex
bytecode, `spec` and `spec_builtin` for versioned specifications, and
`spec_extract` for extracting specifications from a Hermes checkout. None of
these requires a separate crate dependency.

## Cargo examples

Run the no-setup, in-memory workflow:

```sh
cargo run -p mercury-hbc --example quickstart
```

Compile a `.js` or `.ts` script to HBC 96:

```sh
cargo run -p mercury-hbc --example compile -- input.js output.hbc
```

Decompile HBC 96 to stdout, or pass an output path:

```sh
cargo run -p mercury-hbc --example decompile -- input.hbc output.js
```

Decompile, optionally rename Mercury-generated bindings with an SWC visitor, and
compile the in-memory tree back to HBC:

```sh
cargo run -p mercury-hbc --example roundtrip -- \
  test/box2d.hbc /tmp/box2d-rebuilt.hbc --rename-generated
```

## Command-line interface

The `mercury` binary is an optional target gated by the `cli` feature. Library
users do not need to enable it. Install it from crates.io with:

```sh
cargo install mercury-hbc --features cli
```

From a checkout, run it through Cargo:

```sh
cargo run -p mercury-hbc --features cli --bin mercury -- compile input.js -o /tmp/example.hbc
cargo run -p mercury-hbc --features cli --bin mercury -- decompile /tmp/example.hbc -o /tmp/recovered.js
```

## Native source-compilation contract

Native compilation currently targets HBC 96 scripts. Supported control flow
includes blocks, `if`/`else`, `while`, `do…while`, `for`, `for…in`, `for…of`,
`switch`, unlabeled `break` and `continue`, `return`, `throw`, and
`try`/`catch`/`finally`. Function declarations are hoisted, and strict directive
prologues set the corresponding HBC function behavior.

Functions and bindings include:

- `var`, `let`, and `const`, including lexical shadowing and TDZ checks;
- regular and anonymous functions, recursion, constructors, and `this`;
- arrow functions with expression or block bodies and lexical `this`/`arguments`;
- parent-linked captured environments, shared sibling mutation, and fresh
  environments across outer calls and loop iterations;
- default and rest parameters, array and object binding patterns, and the
  ordinary unmapped `arguments` object.

Expressions and runtime values include:

- primitive, array, object, regular-expression, and template literals;
- arithmetic, bitwise, comparison, coercion, update, assignment, compound
  assignment, sequence, conditional, and short-circuit operators;
- property reads/writes, method receivers, accessors, computed keys, `__proto__`,
  deletion, `new.target`, and constructor return selection;
- fixed and spread calls, spread constructors, object spread/rest, and array
  spread;
- UTF-16 strings and property keys, including lone surrogates;
- real exception tables and iterator closing on abrupt completion.

TypeScript annotations are stripped and supported runtime constructs are lowered
before HBC generation. Array binding patterns use `Array.from` and array `slice`;
they assume those standard intrinsics have not been replaced.

Destructuring assignments, block-level function declarations, source-authored
async and generator functions, classes, unbundled modules, labeled control flow,
and `for await…of` currently return `Error::Unsupported`. This list describes the
source compiler only: the decompiler has independent bytecode coverage.

## Decompilation contract

The output is an executable reconstruction, not the original source. Functions
retain register temporaries and use a `while`/`switch` basic-block dispatcher to
preserve instruction and exception order without guessing high-level structure.

Within the HBC 96 container contract, lowering covers constants, closures,
mutable captured environments, global and property access, calls and
construction, arithmetic and coercion, arrays and objects, spread and rest,
iteration, dense switch tables, exceptions, regular expressions, BigInts, direct
eval, typed 32-bit operations, generator suspension, and async completion.
Generator and async adapters retain frame state across `next`, `throw`, `return`,
`yield*`, and fulfilled or rejected awaits. Hermes' ES6 class helper calls remain
bytecode-driven.

Generated code captures standard intrinsics such as `Reflect.apply`,
`Reflect.defineProperty`, `Object.create`, `RegExp`, `BigInt`, `DataView`, and
`Math.imul` when needed. It assumes those intrinsics retain their standard
behavior. Proxy/global interception, arbitrary host hooks, exact reflective
function source, and caller stacks are outside the compatibility contract.

String-switch metadata is not implemented. Some unsupported container options
and global names are rejected explicitly. Original comments, formatting, local
names, TypeScript types, and byte-identical output cannot be recovered from HBC.
Successful source compilation also does not imply that every arbitrary HBC file
can be decompiled and rebuilt.

## Errors

All high-level operations return `mercury_hbc::Error`:

- `Parse` contains located source diagnostics;
- `Unsupported` identifies an unsupported version, syntax construct, or container
  feature;
- `Bytecode` reports malformed input or an encoding invariant failure;
- `Version` reports expected and actual HBC versions;
- `Compiler` reports an external `hermesc` process failure;
- `Io` wraps filesystem and process I/O errors.

## Documentation and verification

Build the API documentation and run its examples:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc -p mercury-hbc --no-deps
cargo test --doc -p mercury-hbc
cargo check -p mercury-hbc --examples
```

Run the self-contained tests:

```sh
cargo test -p mercury-hbc --all-features
```

Execution tests require a Hermes runtime and, for fixtures authored from source,
its compiler:

```sh
HERMESC_BIN=/absolute/path/to/hermesc HERMES_BIN=/absolute/path/to/hermes \
  cargo test -p mercury-hbc --all-features -- --include-ignored
```

The corpus harness covers 12 focused fixtures and 49 generated programs at `-O0`
and `-O`, for 122 cases. Each reference HBC is executed, decompiled to SWC,
rebuilt with `HbcCompiler`, and executed again. Exit status, stdout, and
normalized stderr must match. See the workspace
[test guide](../../test/README.md) for external corpus controls and fixture
commands.

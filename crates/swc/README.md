# mercury-swc

A first source-level module for Mercury. It exposes real SWC Rust AST structs,
keeps their source/comment/binding context, compiles scripts through an explicitly
configured Hermes compiler, and decompiles a small HBC-96 subset into executable
SWC nodes.

## Interface

- `SwcModule::parse(name, source, language, kind)` parses JavaScript or TypeScript,
  as a script or ES module. Fatal and recoverable syntax errors are returned with
  filename, line, and column. TypeScript is not type-checked.
- `program`, `comments`, and `source_map` expose SWC data. `with_ast` runs an
  editing closure inside this module's SWC globals; `transform` applies an SWC
  pass. Preserve binding contexts when renaming identifiers, and use fresh SWC
  contexts when introducing bindings. The `ast`, `visit`, and `swc_core`
  re-exports use the same dependency versions as the module.
- `print()` prints the current JS/TS tree with comments. `javascript()` lowers
  TypeScript on a copy, then runs hygiene and fixer before code generation.
  Parsing already runs SWC's resolver. Source maps are retained as input context;
  exporting a generated source-map file is not implemented yet.
- `HermesCompiler::new(executable, 96).compile(&module)` invokes that compiler
  with `-O -g0 -emit-binary`, validates the returned HBC version and container,
  and returns bytes. It never executes the program. Temporary files are isolated
  per invocation and removed automatically. Compiler stderr is included on error.
- `decompile(&bytes)` constructs SWC nodes directly from Mercury's decoded raw
  IR and a private basic-block graph. Opcode lowering does not generate text and
  parse that text back into an AST; generator support adds a fixed embedded
  runtime as SWC statements around those directly constructed nodes.

SWC 75 is selected as a compatible family through `swc_core`; Cargo.lock records
its resolved dependencies. SWC Rust interfaces are version-sensitive, so callers
should use the re-exported types or the same dependency family.

```rust,ignore
use mercury_swc::{HermesCompiler, SourceKind, SourceLanguage, SwcModule, decompile};

let source = SwcModule::parse(
    "example.ts", "const x: number = 4; print(x);",
    SourceLanguage::TypeScript, SourceKind::Script,
)?;
let compiler = HermesCompiler::new("/path/to/hermesc", 96);
let bytes = compiler.compile(&source)?;
let recovered = decompile(&bytes)?;
println!("{}", recovered.print());
```

## CLI

From the workspace root:

```sh
cargo run -p mercury-cli -- compile crates/swc/tests/fixtures/control_flow.js \
  --hermesc /absolute/path/to/hermesc -o /tmp/control-flow.hbc
cargo run -p mercury-cli -- decompile /tmp/control-flow.hbc -o /tmp/control-flow.js
cargo run -p mercury-cli -- compile /tmp/control-flow.js \
  --hermesc /absolute/path/to/hermesc -o /tmp/control-flow-rebuilt.hbc
```

`HERMESC_BIN` is an alternative to `--hermesc`. The CLI treats `.ts` inputs as
TypeScript and other inputs as JavaScript scripts. ES modules can be parsed and
printed through the library, but compilation currently requires a bundled
script. JSX/TSX and compatibility downleveling are not enabled.

## Current decompilation contract

The result is an executable reconstruction, not the original source. Each
function retains register temporaries and uses a `while`/`switch` block dispatcher.
This preserves instruction order and handles conditional branches and loops
without guessing high-level structure. A later analysis pass can recover
expressions and structured `if`/`while` statements.

The initial subset includes constants, parameter loads, functions with mutable
captured variables, global access, property reads/writes, fixed-arity and general
calls, common arithmetic/comparisons, conditional/unconditional branches,
empty, sparse, buffered, and dynamically populated array allocation, returns,
buffer-backed object literals, dynamic own-property definitions, returns, and
throws. Dense integer switch tables are decoded from their trailing function data
and lowered into the dispatcher. Function names and strictness are retained.
Unknown opcodes fail with function index and instruction offset; malformed branch
targets, switch tables, and literal buffers fail before emitting a tree.

Exception-handler ranges are part of the raw IR and split dispatcher blocks at
every protected boundary. Generated `try`/`catch` routing follows Hermes' table
order, so exceptions from explicit throws, property operations, and nested calls
resume at the matching `Catch` opcode. Nested catches and finally cleanup paths
remain bytecode-driven rather than being restructured into the original source.

Closure environments are reconstructed as a private parent-linked slot structure.
This preserves mutation shared by sibling closures, independent environments from
separate outer calls, and captures across multiple lexical levels. The structure
is an implementation detail rather than part of the module interface.

Generator and async frames retain their registers, arguments, receiver, and
closure environment across suspension. The generated iterator adapter implements
`next`, `throw`, `return`, completion, re-entry checks, and `Symbol.iterator`;
Hermes' delegated-yield builtins preserve `yield*` forwarding. Async wrappers
drive the same frames through captured Promises, including fulfilled and rejected
awaits. Exact native generator/async function prototypes and reflective source
text are not reconstructed.

String-switch metadata and dynamic eval are not implemented. The decompiler also
rejects non-finite literal doubles, unpaired UTF-16 surrogates and function/global
names outside its supported identifier subset. Source comments, original variable
names, original TypeScript types, and byte-identical recompilation cannot be
recovered from HBC.

Generated calls assume the standard, unmodified `Reflect.apply` intrinsic;
dynamic array and object initializers also use `Reflect.defineProperty` to preserve
Hermes' define-own behavior in the presence of inherited setters. Static buffered
object properties become computed SWC object properties so a `__proto__` key keeps
ordinary own-property semantics. Global lookups assume ordinary globals;
proxy/global interception and mutated intrinsics are outside this first contract.
Regular expressions and BigInts use captured standard `RegExp` and `BigInt`
constructors; BigInt table bytes are decoded as signed little-endian values before
JavaScript generation.
Reflective details such as function source text and caller stacks will differ.
Reading/rebuilding arbitrary HBC is not implied by successful source compilation;
supported compilation syntax is broader than the decompiler subset.

## Verification

`cargo test -p mercury-swc` checks JS/TS parsing and printing, scope identity,
visitor edits, diagnostics, the committed bytecode fixture, and generated JS
syntax without an installed Hermes toolchain.

For executable checks:

```sh
HERMESC_BIN=/absolute/path/to/hermesc HERMES_BIN=/absolute/path/to/hermes \
  cargo test -p mercury-swc -- --include-ignored
```

The execution tests cover arithmetic, calls, an if/else and loop, short-circuit
logic, a receiver whose `.call` property has been replaced, side effects, NaN-like
relational comparisons, helper-name collisions, TS enum lowering, and mutable
captured variables. Closure checks cover independent outer calls, sibling
closures sharing one environment, and captures across multiple lexical levels.
Array checks cover length, holes, indexed mutation, every serialized primitive
kind, dynamic elements, closure elements, and inherited index setters. The main
Object checks cover serialized primitive values, key order, numeric and computed
keys, duplicate keys, `__proto__`, descriptor flags, inherited setters, and
custom, null, or primitive prototype operands. The main loop prints `18` after
recompilation; integer-switch checks cover shared targets, in-range gaps, default
targets, and non-integer inputs. Exception checks cover nested catches, exceptions
crossing function calls, and finally cleanup on normal and exceptional paths. An
additional runtime-data check covers stateful regular expressions and large
positive and negative BigInt constants. An SWC numeric-literal visitor changes the
main loop to print `28`. Generator fixtures cover independent suspended frames,
captured locals, `next`/`throw`/`return`, cleanup paths, completion, pre-start
actions, the iterator protocol, and `yield*` delegation. Async fixtures cover
multiple fulfilled awaits, rejection through a bytecode catch, captured locals,
and receiver preservation. Every runtime case compares authored HBC execution
with execution after HBC-to-SWC-to-HBC reconstruction.

`tests/fixtures/control_flow.hbc` was generated from the adjacent authored JS
fixture with the local compiler reporting Hermes release 0.12.0 / HBC 96:

```sh
hermesc -O -g0 -emit-binary \
  -out=crates/swc/tests/fixtures/control_flow.hbc \
  crates/swc/tests/fixtures/control_flow.js
```

The integration exposed compact-header bugs affecting small HBC-96 files and
files with preserved generator/async function sources. The binary layer now
distinguishes its two observed version-96 header tails by the debug-offset
location, retains the selected layout for writing, and tests both compact
function-source fields and header byte equality against `hex.hbc`. Modelling
producer variants explicitly in the generated specs remains future work.

References: [SWC parser](https://docs.rs/swc_ecma_parser/43.0.0/swc_ecma_parser/),
[TypeScript transform](https://docs.rs/swc_ecma_transforms_typescript/53.0.0/swc_ecma_transforms_typescript/),
[SWC variable management](https://swc.rs/docs/contributing/es-commons/variable-management).

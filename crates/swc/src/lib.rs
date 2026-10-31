//! JavaScript and TypeScript source editing, native Hermes bytecode compilation,
//! and executable bytecode decompilation.
//!
//! `mercury-hbc` connects Mercury's Hermes bytecode machinery to real
//! [SWC](https://swc.rs/) syntax trees. It supports three main workflows:
//!
//! - Parse JavaScript or TypeScript into a [`SwcModule`], inspect or transform
//!   its SWC AST, and print it again.
//! - Compile a supported script directly to HBC 96 or HBC 98 with [`HbcCompiler`],
//!   without invoking `hermesc` or executing the input program.
//! - Decompile supported HBC 96 bytecode into an executable SWC tree with
//!   [`decompile`], optionally edit that tree, and compile it back to HBC.
//!
//! # Quickstart
//!
//! ```
//! use mercury_hbc::{decompile, HbcCompiler, SourceKind, SourceLanguage, SwcModule};
//!
//! fn main() -> Result<(), mercury_hbc::Error> {
//!     let module = SwcModule::parse(
//!         "example.ts",
//!         "const answer: number = 40 + 2; print(answer);",
//!         SourceLanguage::TypeScript,
//!         SourceKind::Script,
//!     )?;
//!
//!     // Native compilation needs no external Hermes installation.
//!     let bytecode = HbcCompiler::new(96).compile(&module)?;
//!     assert_eq!(&bytecode[8..12], &96_u32.to_le_bytes());
//!
//!     // Decompilation returns another editable SWC-backed module.
//!     let recovered = decompile(&bytecode)?;
//!     assert!(!recovered.print().is_empty());
//!     Ok(())
//! }
//! ```
//!
//! # Editing SWC trees
//!
//! [`SwcModule::with_ast`] runs a closure with the module's SWC globals installed.
//! Use it with the re-exported [`ast`] and [`visit`] types to avoid depending on a
//! second, potentially incompatible SWC version. [`SwcModule::transform`] applies
//! an SWC [`Pass`](swc_core::ecma::ast::Pass). New bindings must have fresh or
//! deliberately preserved syntax contexts; renaming an identifier's text alone is
//! not always sufficient for arbitrary source transformations.
//!
//! # Compatibility and limitations
//!
//! Native compilation targets **HBC 96 and HBC 98**; decompilation targets
//! **HBC 96**. Source compilation accepts scripts, not unbundled ES modules, and
//! returns [`Error::Unsupported`] for syntax outside its implemented subset.
//! TypeScript is transpiled, not type-checked. Decompilation preserves executable
//! behavior rather than original formatting, comments, local names, or high-level
//! control flow.
//!
//! [`HermesCompiler`] is a separate adapter for callers that explicitly configure
//! an external `hermesc` executable; it is not used by [`HbcCompiler`].
//!
//! # Lower-level APIs
//!
//! The [`binary`], [`ir`], [`asm`], and [`regex`] modules expose Mercury's
//! container codec, intermediate representations, semantic assembler, and Hermes
//! regex compiler. Versioned specifications are available through [`spec`],
//! [`spec_builtin`], and [`spec_extract`]. All are part of this single crate.
//!
//! The crate README documents the detailed source-language and bytecode contracts.

#![warn(missing_docs)]

mod ast_builder;
#[allow(missing_docs)]
pub mod asm;
#[allow(missing_docs)]
pub mod binary;
mod cfg;
mod compiler;
mod decompile;
#[allow(missing_docs)]
pub mod disasm;
#[allow(missing_docs)]
pub mod ir;
mod literal;
mod native_compiler;
#[allow(missing_docs)]
pub mod regex;
mod source;
#[allow(missing_docs)]
pub mod spec;
/// Embedded Hermes bytecode specifications.
#[allow(missing_docs)]
pub mod spec_builtin;
#[allow(missing_docs)]
pub mod spec_extract;

pub use compiler::HermesCompiler;
pub use decompile::decompile;
pub use native_compiler::HbcCompiler;
pub use source::{SourceKind, SourceLanguage, SwcModule};
pub use swc_core;
pub use swc_core::ecma::{ast, visit};

/// An error produced while parsing, compiling, decompiling, or performing I/O.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The source could not be parsed; the string contains located diagnostics.
    #[error("source parse failed: {0}")]
    Parse(String),
    /// The requested source construct, container feature, or version is unsupported.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// An explicitly configured external Hermes compiler failed.
    #[error("Hermes compiler failed: {0}")]
    Compiler(String),
    /// The bytecode version differs from the version required by the operation.
    #[error("expected bytecode version {expected}, got {actual}")]
    Version {
        /// The bytecode version required by the compiler or decompiler.
        expected: u32,
        /// The version found in the input or produced by an external compiler.
        actual: u32,
    },
    /// The bytecode is malformed or violates an HBC invariant.
    #[error("invalid bytecode: {0}")]
    Bytecode(String),
    /// An underlying filesystem or external-compiler I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

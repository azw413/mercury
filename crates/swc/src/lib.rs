//! SWC trees for source editing, native HBC 96 compilation, an optional external
//! compiler adapter, and bytecode decompilation. See the crate README for the
//! supported subsets.
mod ast_builder;
mod cfg;
mod compiler;
mod decompile;
mod literal;
mod native_compiler;
mod source;

pub use compiler::HermesCompiler;
pub use decompile::decompile;
pub use native_compiler::HbcCompiler;
pub use source::{SourceKind, SourceLanguage, SwcModule};
pub use swc_core;
pub use swc_core::ecma::{ast, visit};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("source parse failed: {0}")]
    Parse(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("Hermes compiler failed: {0}")]
    Compiler(String),
    #[error("expected bytecode version {expected}, got {actual}")]
    Version { expected: u32, actual: u32 },
    #[error("invalid bytecode: {0}")]
    Bytecode(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

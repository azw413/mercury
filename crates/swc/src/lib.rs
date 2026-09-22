//! SWC trees for source editing, a configured Hermes compiler, and a deliberately
//! limited bytecode decompiler. See the crate README for the supported subset.
mod ast_builder;
mod cfg;
mod compiler;
mod decompile;
mod literal;
mod source;

pub use compiler::HermesCompiler;
pub use decompile::decompile;
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

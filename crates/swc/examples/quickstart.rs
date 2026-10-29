//! Compile TypeScript to HBC 96 and decompile it, entirely in memory.
//!
//! Run with: cargo run -p mercury-hbc --example quickstart

use mercury_hbc::{HbcCompiler, SourceKind, SourceLanguage, SwcModule, decompile};

fn main() -> Result<(), mercury_hbc::Error> {
    let module = SwcModule::parse(
        "quickstart.ts",
        "const answer: number = 40 + 2; print(answer);",
        SourceLanguage::TypeScript,
        SourceKind::Script,
    )?;

    let bytecode = HbcCompiler::new(96).compile(&module)?;
    println!("Compiled {} bytes of HBC 96.", bytecode.len());

    let recovered = decompile(&bytecode)?;
    println!("\nRecovered JavaScript:\n{}", recovered.print());
    Ok(())
}

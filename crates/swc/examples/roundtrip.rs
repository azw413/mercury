//! Decompile an HBC-96 file to SWC, optionally edit its generated bindings, and
//! compile the in-memory AST back to HBC without invoking `hermesc`.
//!
//! Run with:
//! cargo run -p mercury-swc --example roundtrip -- input.hbc output.hbc [--rename-generated]

use std::{env, fs, process};

use mercury_swc::{
    HbcCompiler,
    ast::Ident,
    decompile,
    visit::{VisitMut, VisitMutWith},
};

struct RenameGeneratedBindings;

impl VisitMut for RenameGeneratedBindings {
    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        if let Some(suffix) = identifier.sym.as_ref().strip_prefix("_mercury_") {
            identifier.sym = format!("_roundtrip_{suffix}").into();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let Some(input) = args.next() else {
        usage();
    };
    let Some(output) = args.next() else {
        usage();
    };
    let rename_generated = match args.next() {
        None => false,
        Some(flag) if flag == "--rename-generated" => true,
        Some(_) => usage(),
    };
    if args.next().is_some() {
        usage();
    }

    let bytes = fs::read(input)?;
    let mut module = decompile(&bytes)?;
    if rename_generated {
        module.with_ast(|program| program.visit_mut_with(&mut RenameGeneratedBindings));
    }
    let rebuilt = HbcCompiler::new(96).compile(&module)?;
    fs::write(output, rebuilt)?;
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: roundtrip <input.hbc> <output.hbc> [--rename-generated]");
    process::exit(2);
}

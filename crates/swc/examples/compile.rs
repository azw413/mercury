//! Compile JavaScript or TypeScript source directly to HBC 96.
//!
//! Run with:
//! cargo run -p mercury-swc --example compile -- input.js output.hbc

use std::{env, fs, path::Path, process};

use mercury_swc::{HbcCompiler, SourceKind, SourceLanguage, SwcModule};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let Some(input) = args.next() else {
        usage();
    };
    let Some(output) = args.next() else {
        usage();
    };
    if args.next().is_some() {
        usage();
    }

    let language = match Path::new(&input)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("ts") => SourceLanguage::TypeScript,
        _ => SourceLanguage::JavaScript,
    };
    let source = fs::read_to_string(&input)?;
    let module = SwcModule::parse(
        &Path::new(&input).to_string_lossy(),
        &source,
        language,
        SourceKind::Script,
    )?;
    let bytes = HbcCompiler::new(96).compile(&module)?;
    fs::write(output, bytes)?;
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: compile <input.js|input.ts> <output.hbc>");
    process::exit(2);
}

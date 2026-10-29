//! Decompile an HBC-96 file through Mercury's SWC AST and emit JavaScript.
//!
//! Run with:
//! cargo run -p mercury-hbc --example decompile -- input.hbc [output.js]

use std::{env, fs, io::Write, path::PathBuf, process};

use mercury_hbc::decompile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let Some(input) = args.next() else {
        usage();
    };
    let output = args.next().map(PathBuf::from);
    if args.next().is_some() {
        usage();
    }

    let bytes = fs::read(input)?;
    let module = decompile(&bytes)?;
    let javascript = module.print();

    if let Some(output) = output {
        fs::write(output, javascript)?;
    } else {
        std::io::stdout().write_all(javascript.as_bytes())?;
    }
    Ok(())
}

fn usage() -> ! {
    eprintln!("usage: decompile <input.hbc> [output.js]");
    process::exit(2);
}

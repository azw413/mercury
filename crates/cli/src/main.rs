use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mercury_binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_spec_builtin::{load_spec, supported_versions};
use mercury_spec_extract::{Extractor, ExtractorConfig};
use mercury_spec_extract::hermes_dec::compare_against_hermes_dec;

#[derive(Debug, Parser)]
#[command(name = "mercury")]
#[command(about = "Hermes bytecode reverse engineering toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Versions,
    Decode {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    ExtractSpec {
        #[arg(long, default_value = "../hermes")]
        hermes_repo: String,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value = "spec/generated")]
        output_dir: String,
        #[arg(long)]
        compare_hermes_dec: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Versions => {
            for version in supported_versions() {
                println!("{version}");
            }
        }
        Command::Decode { input, output } => {
            let bytes = fs::read(&input)
                .with_context(|| format!("failed to read {}", input.display()))?;
            let version = detect_bytecode_version(&bytes)?;
            let spec = load_spec(version)
                .with_context(|| format!("no embedded spec for bytecode version {version}"))?;
            let container = parse_hbc_container_with_spec(&bytes, &spec.container)
                .with_context(|| format!("failed to parse {}", input.display()))?;
            let raw = decode_raw_module(&container, &bytes, &spec.bytecode)
                .with_context(|| format!("failed to decode {}", input.display()))?;
            let body = render_raw_module(&input, &raw);

            if let Some(output) = output {
                fs::write(&output, body)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                print!("{body}");
            }
        }
        Command::ExtractSpec {
            hermes_repo,
            tag,
            output_dir,
            compare_hermes_dec,
        } => {
            let extractor = Extractor::new(ExtractorConfig { hermes_repo });
            if let Some(tag) = tag {
                let spec = extractor.extract_tag(&tag)?;
                let output_path = format!("{output_dir}/hbc{}.json", spec.bytecode_version);
                extractor.write_json(&spec, &output_path)?;
                println!(
                    "wrote {}",
                    output_path,
                );
                println!(
                    "bytecode_version={} source_tag={} instructions={} file_header_fields={} function_header_fields={}",
                    spec.bytecode_version,
                    spec.hermes_tag,
                    spec.bytecode.instructions.len(),
                    spec.container.file_header.fields.len(),
                    spec.container.function_header.fields.len(),
                );
                if let Some(hermes_dec_root) = compare_hermes_dec {
                    let comparison = compare_against_hermes_dec(&spec, hermes_dec_root)?;
                    println!(
                        "compared against {}",
                        comparison.opcode_module_path.display()
                    );
                    if comparison.opcode_mismatches.is_empty()
                        && comparison.file_header_mismatches.is_empty()
                    {
                        println!("hermes-dec comparison: OK");
                    } else {
                        println!("hermes-dec comparison: mismatches found");
                        for mismatch in comparison.opcode_mismatches {
                            println!("opcode mismatch: {mismatch}");
                        }
                        for mismatch in comparison.file_header_mismatches {
                            println!("container mismatch: {mismatch}");
                        }
                    }
                }
            } else {
                for tag in extractor.list_tags()? {
                    println!("{tag}");
                }
            }
        }
    }

    Ok(())
}

fn detect_bytecode_version(bytes: &[u8]) -> anyhow::Result<u32> {
    if bytes.len() < 12 {
        bail!("input is too short to contain a Hermes file header");
    }

    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[8..12]);
    Ok(u32::from_le_bytes(buf))
}

fn render_raw_module(input: &PathBuf, raw: &mercury_ir::RawModule) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# mercury decode");
    let _ = writeln!(out, "input {}", input.display());
    let _ = writeln!(out, "bytecode_version {}", raw.version);
    let _ = writeln!(out, "function_count {}", raw.function_count);
    let _ = writeln!(out, "function_bodies_start {}", raw.sections.function_bodies_start);
    let _ = writeln!(out);

    for function in &raw.functions {
        let _ = writeln!(
            out,
            ".function {} offset={} size={} params={} frame={} env={} read_cache={} write_cache={} flags=strict:{} exception:{} debug:{} overflow:{} prohibit:{}",
            function.function_index,
            function.offset,
            function.bytecode_size_in_bytes,
            function.param_count,
            function.frame_size,
            function.environment_size,
            function.highest_read_cache_index,
            function.highest_write_cache_index,
            function.flags.strict_mode,
            function.flags.has_exception_handler,
            function.flags.has_debug_info,
            function.flags.overflowed,
            function.flags.prohibit_invoke,
        );

        for instruction in &function.instructions {
            let _ = writeln!(
                out,
                "  {:04x}: {:<32} {}",
                instruction.offset,
                instruction.name,
                render_operands(&instruction.operands)
            );
        }

        let _ = writeln!(out, ".end");
        let _ = writeln!(out);
    }

    out
}

fn render_operands(operands: &[mercury_ir::RawOperand]) -> String {
    operands
        .iter()
        .map(|operand| match operand {
            mercury_ir::RawOperand::U8(value) => value.to_string(),
            mercury_ir::RawOperand::U16(value) => value.to_string(),
            mercury_ir::RawOperand::U32(value) => value.to_string(),
            mercury_ir::RawOperand::I8(value) => value.to_string(),
            mercury_ir::RawOperand::I32(value) => value.to_string(),
            mercury_ir::RawOperand::F64(value) => value.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

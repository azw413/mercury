use clap::{Parser, Subcommand};
use mercury_spec_extract::{Extractor, ExtractorConfig};

#[derive(Debug, Parser)]
#[command(name = "mercury")]
#[command(about = "Hermes bytecode reverse engineering toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ExtractSpec {
        #[arg(long, default_value = "../hermes")]
        hermes_repo: String,
        #[arg(long)]
        tag: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ExtractSpec { hermes_repo, tag } => {
            let extractor = Extractor::new(ExtractorConfig { hermes_repo });
            if let Some(tag) = tag {
                let spec = extractor.extract_tag(&tag)?;
                println!(
                    "tag={} bytecode_version={} instructions={} file_header_fields={}",
                    spec.hermes_tag,
                    spec.bytecode_version,
                    spec.bytecode.instructions.len(),
                    spec.container.file_header.fields.len()
                );
            } else {
                for tag in extractor.list_tags()? {
                    println!("{tag}");
                }
            }
        }
    }

    Ok(())
}

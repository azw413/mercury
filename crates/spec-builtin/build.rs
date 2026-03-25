use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").context("missing CARGO_MANIFEST_DIR")?);
    let spec_dir = manifest_dir
        .parent()
        .context("crate dir should have parent")?
        .parent()
        .context("workspace root should have parent")?
        .join("spec/generated");

    println!("cargo:rerun-if-changed={}", spec_dir.display());

    let mut specs = fs::read_dir(&spec_dir)
        .with_context(|| format!("failed to read {}", spec_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    specs.sort();

    let out_dir = PathBuf::from(env::var("OUT_DIR").context("missing OUT_DIR")?);
    let output = out_dir.join("registry.rs");
    fs::write(&output, render_registry(&specs)?)
        .with_context(|| format!("failed to write {}", output.display()))?;
    Ok(())
}

fn render_registry(specs: &[PathBuf]) -> Result<String> {
    let mut entries = Vec::new();
    let mut versions = Vec::new();

    for spec in specs {
        let file_name = spec
            .file_name()
            .and_then(|value| value.to_str())
            .with_context(|| format!("invalid spec path {}", spec.display()))?;
        let version = parse_version(file_name)
            .with_context(|| format!("invalid generated spec filename {file_name}"))?;
        let const_name = format!("HBC_{version}");
        let abs_path = spec
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", spec.display()))?;

        entries.push(format!(
            "EmbeddedSpec {{ version: {version}, json: include_bytes!(r#\"{}\"#) }}",
            abs_path.display()
        ));
        versions.push(version);

        println!("cargo:rerun-if-changed={}", abs_path.display());
        let _ = const_name;
    }

    let versions_literal = versions
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let entries_literal = entries.join(",\n    ");

    Ok(format!(
        "const SUPPORTED_VERSIONS: &[u32] = &[{versions_literal}];\n\
         const EMBEDDED_SPECS: &[EmbeddedSpec] = &[\n    {entries_literal}\n];\n"
    ))
}

fn parse_version(file_name: &str) -> Result<u32> {
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|value| value.to_str())
        .context("missing stem")?;
    let version = stem
        .strip_prefix("hbc")
        .context("missing hbc prefix")?
        .parse::<u32>()
        .context("invalid version digits")?;
    Ok(version)
}

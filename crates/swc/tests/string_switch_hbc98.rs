use std::{fs, process::Command};

use mercury_hbc::binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_hbc::spec_builtin::load_spec;
use mercury_hbc::{HbcCompiler, decompile};

const SOURCE: &str = r#"
function classify(key) {
  switch (key) {
    case "alpha": return 1;
    case "beta": return 2;
    case "gamma": return 3;
    case "delta": return 4;
    case "epsilon": return 5;
    default: return -1;
    case "zeta": return 6;
    case "eta": return 7;
    case "theta": return 8;
    case "iota": return 9;
    case "kappa": return 10;
  }
}
var inputs = ["beta", "zeta", "kappa", "missing", 7, null, new String("gamma"), "alpha"];
for (var i = 0; i < inputs.length; i++) {
  if (inputs[i] === "beta") continue;
  print(classify(inputs[i]));
}
"#;

fn compile_with_hermesc(hermesc: &std::ffi::OsStr, args: &[&str]) -> (Vec<u8>, String) {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("input.js");
    let binary_path = directory.path().join("input.hbc");
    fs::write(&source_path, SOURCE).unwrap();
    let compile = Command::new(hermesc)
        .args(args)
        .args(["-emit-binary", "-out"])
        .arg(&binary_path)
        .arg(&source_path)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "hermesc failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let dump = Command::new(hermesc)
        .args(args)
        .arg("-dump-bytecode")
        .arg(&source_path)
        .output()
        .unwrap();
    (
        fs::read(&binary_path).unwrap(),
        String::from_utf8(dump.stdout).unwrap(),
    )
}

fn hermesc_mode(hermesc: &std::ffi::OsStr, mode: &str) -> (Vec<u8>, String) {
    compile_with_hermesc(hermesc, &[mode])
}

fn resolve_string(container: &mercury_hbc::binary::HbcContainer, string_id: u32) -> Option<String> {
    let entry = container
        .small_string_table_entries
        .get(string_id as usize)?;
    let (offset, length) = if entry.is_overflowed {
        let overflow = container
            .overflow_string_table_entries
            .get(entry.offset as usize)?;
        (overflow.offset as usize, overflow.length as usize)
    } else {
        (entry.offset as usize, entry.length as usize)
    };
    if entry.is_utf16 {
        let bytes = container.string_storage.get(offset..offset + length * 2)?;
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&words).ok()
    } else {
        String::from_utf8(
            container
                .string_storage
                .get(offset..offset + length)?
                .to_vec(),
        )
        .ok()
    }
}

fn execute(hermes: &std::ffi::OsStr, bytes: &[u8]) -> String {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input.hbc");
    fs::write(&path, bytes).unwrap();
    let output = Command::new(hermes).arg("-b").arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
#[ignore = "requires HERMESC_BIN (HBC 98) and HERMES98_BIN"]
fn string_switch_tables_decode_decompile_and_execute() {
    let hermesc = std::env::var_os("HERMESC_BIN").expect("HERMESC_BIN = HBC 98 hermesc");
    let hermes = std::env::var_os("HERMES98_BIN").expect("HERMES98_BIN = HBC 98 runtime");
    let spec = load_spec(98).unwrap();

    for mode in ["-O0", "-O"] {
        let (bytes, dump) = hermesc_mode(&hermesc, mode);
        if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 98 {
            eprintln!("HERMESC_BIN does not emit HBC 98; skipping");
            return;
        }
        let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
        let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
        let tables = raw
            .functions
            .iter()
            .flat_map(|f| f.string_switch_tables.iter())
            .collect::<Vec<_>>();
        assert_eq!(tables.len(), 1, "{mode}: {dump}");
        let table = tables[0];
        assert_eq!(table.global_index, 0);
        assert_eq!(table.cases.len(), 10);
        // Labels are the ten case strings, unique, and all appear in the
        // dump's table listing.
        let labels = table
            .cases
            .iter()
            .map(|case| resolve_string(&container, case.string_id))
            .collect::<Option<Vec<_>>>()
            .expect("switch case labels are readable strings");
        assert_eq!(labels.len(), 10);
        let label_set: std::collections::BTreeSet<&String> = labels.iter().collect();
        assert_eq!(label_set.len(), 10);
        for label in &labels {
            assert!(
                dump.contains(label.as_str()),
                "{label} missing from dump:\n{dump}"
            );
        }

        // Decompile -> native rebuild -> identical execution.
        let rebuilt = HbcCompiler::new(98)
            .compile(&decompile(&bytes).unwrap())
            .unwrap();
        let reference = execute(&hermes, &bytes);
        assert_eq!(execute(&hermes, &rebuilt), reference, "{mode}");
    }
}

#[test]
#[ignore = "requires HERMESC_BIN (HBC 98) and HERMES98_BIN"]
fn rebuild_preserves_string_switch_instructions() {
    let hermesc = std::env::var_os("HERMESC_BIN").expect("HERMESC_BIN = HBC 98 hermesc");
    let spec = load_spec(98).unwrap();
    for mode in ["-O0", "-O"] {
        let (bytes, _) = hermesc_mode(&hermesc, mode);
        if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 98 {
            eprintln!("HERMESC_BIN does not emit HBC 98; skipping");
            return;
        }
        let rebuilt = HbcCompiler::new(98)
            .compile(&decompile(&bytes).unwrap())
            .unwrap();
        let container = parse_hbc_container_with_spec(&rebuilt, &spec.container).unwrap();
        let raw = decode_raw_module(&container, &rebuilt, &spec.bytecode).unwrap();
        let count = raw
            .functions
            .iter()
            .flat_map(|f| f.string_switch_tables.iter())
            .count();
        assert_eq!(count, 1, "{mode}");
        assert_eq!(container.header.num_string_switch_imms, count as u32);
    }
}

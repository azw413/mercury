use std::fs;
use std::path::PathBuf;

use mercury_spec::HermesSpec;
use mercury_spec_extract::hermes_dec::compare_against_hermes_dec;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory should have a parent")
        .parent()
        .expect("workspace root should exist")
        .to_path_buf()
}

#[test]
fn generated_hbc89_json_matches_hermes_dec_with_only_known_gaps() {
    let workspace_root = workspace_root();
    let spec_path = workspace_root.join("spec/generated/hbc89.json");
    let hermes_dec_root = workspace_root
        .parent()
        .expect("workspace parent should exist")
        .join("hermes-dec");

    let spec_body = fs::read_to_string(&spec_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", spec_path.display()));
    let spec: HermesSpec = serde_json::from_str(&spec_body)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", spec_path.display()));

    let comparison = compare_against_hermes_dec(&spec, &hermes_dec_root)
        .unwrap_or_else(|err| panic!("comparison against hermes-dec failed: {err}"));

    assert!(
        comparison.file_header_mismatches.is_empty(),
        "unexpected container mismatches: {:?}",
        comparison.file_header_mismatches
    );

    let expected = vec![
        "operand meanings differ for CreateGeneratorClosureLongIndex: mercury=[None, None, Some(FunctionId)] hermes-dec=[None, None, None]".to_owned(),
        "operand meanings differ for CreateAsyncClosureLongIndex: mercury=[None, None, Some(FunctionId)] hermes-dec=[None, None, None]".to_owned(),
        "operand meanings differ for CreateGeneratorLongIndex: mercury=[None, None, Some(FunctionId)] hermes-dec=[None, None, None]".to_owned(),
    ];

    assert_eq!(
        comparison.opcode_mismatches, expected,
        "unexpected opcode mismatches when validating {} against {}",
        spec_path.display(),
        comparison.opcode_module_path.display()
    );
}

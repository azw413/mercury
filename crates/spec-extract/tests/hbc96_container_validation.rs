use std::fs;
use std::path::PathBuf;

use mercury_spec::HermesSpec;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory should have a parent")
        .parent()
        .expect("workspace root should exist")
        .to_path_buf()
}

#[test]
fn generated_hbc96_json_contains_full_function_and_container_layout() {
    let workspace_root = workspace_root();
    let spec_path = workspace_root.join("spec/generated/hbc96.json");

    let spec_body = fs::read_to_string(&spec_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", spec_path.display()));
    let spec: HermesSpec = serde_json::from_str(&spec_body)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", spec_path.display()));

    assert_eq!(spec.bytecode_version, 96);

    let function_header_fields = spec
        .container
        .function_header
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        function_header_fields,
        vec![
            "offset",
            "paramCount",
            "bytecodeSizeInBytes",
            "functionName",
            "infoOffset",
            "frameSize",
            "environmentSize",
            "highestReadCacheIndex",
            "highestWriteCacheIndex",
            "flags",
        ]
    );

    let flag_fields = spec
        .container
        .function_header_flags
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.bit_width))
        .collect::<Vec<_>>();
    assert_eq!(
        flag_fields,
        vec![
            ("prohibitInvoke", 2),
            ("strictMode", 1),
            ("hasExceptionHandler", 1),
            ("hasDebugInfo", 1),
            ("overflowed", 1),
        ]
    );

    let option_fields = spec
        .container
        .bytecode_options
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.bit_width))
        .collect::<Vec<_>>();
    assert_eq!(
        option_fields,
        vec![
            ("staticBuiltins", 1),
            ("cjsModulesStaticallyResolved", 1),
            ("hasAsync", 1),
        ]
    );

    assert_eq!(spec.container.raw_module.function_info.info_alignment, Some(4));
    assert_eq!(spec.container.raw_module.debug_offsets.alignment, Some(4));

    let subsection_alignments = spec
        .container
        .raw_module
        .function_info
        .subsections
        .iter()
        .map(|section| (section.name.as_str(), section.alignment))
        .collect::<Vec<_>>();
    assert_eq!(
        subsection_alignments,
        vec![
            ("large_function_header", Some(4)),
            ("exception_handler_table", Some(4)),
            ("debug_offsets", Some(4)),
        ]
    );
}

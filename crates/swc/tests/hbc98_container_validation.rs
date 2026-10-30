use std::fs;
use std::path::PathBuf;

use mercury_hbc::spec::HermesSpec;

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn generated_spec() -> HermesSpec {
    let spec_path = package_root().join("spec/generated/hbc98.json");
    let spec_body = fs::read_to_string(&spec_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", spec_path.display()));
    serde_json::from_str(&spec_body)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", spec_path.display()))
}

#[test]
fn generated_hbc98_json_contains_full_function_and_container_layout() {
    let spec = generated_spec();

    assert_eq!(spec.bytecode_version, 98);
    assert_eq!(spec.hermes_tag, "hermes-v250829098.0.19");
    assert_eq!(spec.bytecode.instructions.len(), 219);
    for (opcode, instruction) in spec.bytecode.instructions.iter().enumerate() {
        assert_eq!(instruction.opcode as usize, opcode);
    }

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
            "Offset",
            "ParamCount",
            "LoopDepth",
            "BytecodeSizeInBytes",
            "FunctionName",
            "NumberRegCount",
            "NonPtrRegCount",
            "FrameSize",
            "ReadCacheSize",
            "WriteCacheSize",
            "NumCacheNewObject",
            "PrivateNameCacheSize",
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
            ("ProhibitInvoke", 2),
            ("StrictMode", 1),
            ("HasExceptionHandler", 1),
            ("HasDebugInfo", 1),
            ("Overflowed", 1),
            ("Kind", 2),
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
        vec![("StaticBuiltins", 1), ("CjsModulesStaticallyResolved", 1)]
    );

    let file_header_fields = spec
        .container
        .file_header
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();
    assert!(file_header_fields.contains(&"objShapeTableCount"));
    assert!(file_header_fields.contains(&"numStringSwitchImms"));

    let shape_table = spec
        .container
        .raw_module
        .object_shape_table
        .as_ref()
        .expect("HBC 98 should describe its object shape table");
    assert_eq!(shape_table.alignment, Some(4));
    assert_eq!(shape_table.entry_type, "ShapeTableEntry");

    let section_names = spec
        .container
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect::<Vec<_>>();
    assert!(section_names.contains(&"literal_value_buffer"));
    assert!(section_names.contains(&"object_shape_table"));
    assert!(!section_names.contains(&"unknown_segment"));

    let new_object_with_buffer = spec
        .bytecode
        .instructions
        .iter()
        .find(|instruction| instruction.name == "NewObjectWithBuffer")
        .expect("HBC 98 should contain NewObjectWithBuffer");
    let operand_kinds = new_object_with_buffer
        .operands
        .iter()
        .map(|operand| operand.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(operand_kinds, vec!["Reg8", "UInt16", "UInt16"]);
    assert!(
        spec.bytecode
            .instructions
            .iter()
            .any(|instruction| instruction.name == "CreateGenerator")
    );
}

#[test]
fn hbc98_spec_is_available_from_the_embedded_registry() {
    let generated = generated_spec();
    let embedded = mercury_hbc::spec_builtin::load_spec(98)
        .expect("embedded HBC 98 specification should exist");

    assert_eq!(embedded.hermes_tag, generated.hermes_tag);
    assert_eq!(embedded.bytecode_version, generated.bytecode_version);
    assert_eq!(
        embedded.bytecode.instructions.len(),
        generated.bytecode.instructions.len()
    );
    assert_eq!(
        embedded.container.function_header.fields.len(),
        generated.container.function_header.fields.len()
    );
}

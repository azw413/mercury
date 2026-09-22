use mercury_swc::{Error, SourceKind, SourceLanguage, SwcModule, ast::*, decompile};

#[test]
fn committed_compiler_fixture_decompiles_to_real_nodes_and_prints_valid_js() {
    let module = decompile(include_bytes!("fixtures/control_flow.hbc")).unwrap();
    assert!(matches!(module.program, Program::Script(_)));
    let text = module.print();
    assert!(text.contains("while(true)") || text.contains("while (true)"));
    assert!(text.contains("switch"));
    assert!(text.contains("calculate"));
    SwcModule::parse(
        "decompiled.js",
        &text,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    assert_eq!(text, module.print());
}

#[test]
fn malformed_or_other_version_bytecode_is_rejected() {
    assert!(decompile(&[]).is_err());
    let mut bytes = include_bytes!("fixtures/control_flow.hbc").to_vec();
    bytes[8..12].copy_from_slice(&94u32.to_le_bytes());
    assert!(matches!(
        decompile(&bytes),
        Err(Error::Version {
            expected: 96,
            actual: 94
        })
    ));
    bytes[8..12].copy_from_slice(&96u32.to_le_bytes());
    bytes[0] = 0;
    assert!(matches!(decompile(&bytes), Err(Error::Bytecode(_))));
}

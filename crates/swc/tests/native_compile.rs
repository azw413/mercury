use std::{fs, process::Command};

use mercury_binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_spec_builtin::load_spec;
use mercury_swc::{HbcCompiler, SourceKind, SourceLanguage, SwcModule, decompile};

fn compile(source: &str, language: SourceLanguage) -> Vec<u8> {
    let module = SwcModule::parse("input", source, language, SourceKind::Script).unwrap();
    HbcCompiler::new(96).compile(&module).unwrap()
}

#[test]
fn compiles_swc_ast_directly_into_hbc96() {
    let bytes = compile(
        "var answer: number = 40 + 2; print(answer);",
        SourceLanguage::TypeScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let names = raw.functions[0]
        .instructions
        .iter()
        .map(|instruction| instruction.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(container.header.version, 96);
    assert_eq!(raw.functions.len(), 1);
    assert_eq!(raw.functions[0].param_count, 1);
    assert_eq!(
        names,
        [
            "DeclareGlobalVar",
            "LoadConstUInt8",
            "LoadConstUInt8",
            "Add",
            "GetGlobalObject",
            "PutById",
            "GetGlobalObject",
            "TryGetById",
            "LoadConstUndefined",
            "GetGlobalObject",
            "TryGetById",
            "Call2",
            "Mov",
            "LoadConstUndefined",
            "Ret",
        ]
    );

    let recovered = decompile(&bytes).unwrap().print();
    assert!(recovered.contains("var answer;"));
    assert!(recovered.contains(" = 40;"));
    assert!(recovered.contains(" + _mercury_r1"));
    assert!(recovered.contains("_mercury_apply"));
}

#[test]
fn compiles_property_reads_writes_and_receiver_calls() {
    let bytes = compile(
        "var object = Math; object.value = 42; print(object.value); object.max(1, 2);",
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let names = raw.functions[0]
        .instructions
        .iter()
        .map(|instruction| instruction.name.as_str())
        .collect::<Vec<_>>();

    assert!(names.contains(&"PutById"));
    assert!(names.contains(&"GetById"));
    assert!(names.contains(&"Call2"));
    assert!(names.contains(&"Call3"));
}

#[test]
fn rejects_unsupported_syntax_at_the_native_boundary() {
    let module = SwcModule::parse(
        "input.js",
        "if (true) print(1);",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let error = HbcCompiler::new(96).compile(&module).unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported: if statements are not supported by native compilation yet"
    );
}

#[test]
fn typeof_an_unbound_global_does_not_use_a_throwing_lookup() {
    let bytes = compile("print(typeof missing);", SourceLanguage::JavaScript);
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let instructions = &raw.functions[0].instructions;
    let typeof_index = instructions
        .iter()
        .position(|instruction| instruction.name == "TypeOf")
        .unwrap();

    assert_eq!(instructions[typeof_index - 1].name, "GetById");
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_hbc_executes_without_hermes_compiler() {
    let bytes = compile(
        "var answer = 40 + 2; print(answer); var object = Math; object.value = answer; print(object.value); print(Math.max(7, 3)); print(typeof missing);",
        SourceLanguage::JavaScript,
    );
    let path = std::env::temp_dir().join(format!(
        "mercury-native-compile-{}-{}.hbc",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, bytes).unwrap();
    let hermes = std::env::var_os("HERMES_BIN").expect("HERMES_BIN must point to Hermes 0.12");
    let output = Command::new(hermes).arg(&path).output().unwrap();
    let _ = fs::remove_file(path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "42\n42\n7\nundefined\n"
    );
}

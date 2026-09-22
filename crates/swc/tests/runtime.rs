use mercury_swc::{
    HermesCompiler, SourceKind, SourceLanguage, SwcModule,
    ast::Number,
    decompile,
    visit::{VisitMut, VisitMutWith},
};
use std::{fs, path::PathBuf, process::Command};
fn compiler() -> HermesCompiler {
    HermesCompiler::new(
        PathBuf::from(
            std::env::var_os("HERMESC_BIN")
                .expect("set HERMESC_BIN to a version-96 Hermes compiler"),
        ),
        96,
    )
}
fn execute(bytes: &[u8]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.hbc");
    fs::write(&path, bytes).unwrap();
    let output = Command::new(
        std::env::var_os("HERMES_BIN").expect("set HERMES_BIN to a version-96 runtime"),
    )
    .arg("-b")
    .arg(path)
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn source_bytecode_ast_edit_bytecode_executes() {
    let compiler = compiler();
    let source = SwcModule::parse(
        "control_flow.js",
        include_str!("fixtures/control_flow.js"),
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&source).unwrap();
    assert_eq!(execute(&original), "18\n");
    let mut ast = decompile(&original).unwrap();
    let rebuilt = compiler.compile(&ast).unwrap();
    assert_eq!(execute(&rebuilt), "18\n");
    struct Edit;
    impl VisitMut for Edit {
        fn visit_mut_number(&mut self, n: &mut Number) {
            if n.value == 10.0 {
                n.value = 20.0;
                n.raw = None;
            }
        }
    }
    ast.with_ast(|p| p.visit_mut_with(&mut Edit));
    assert_eq!(execute(&compiler.compile(&ast).unwrap()), "28\n");
}
#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn typescript_and_captured_closures_compile_and_execute() {
    let compiler = compiler();
    let ts = SwcModule::parse(
        "example.ts",
        "enum Mode { A = 4 } const x: number = Mode.A; print(x);",
        SourceLanguage::TypeScript,
        SourceKind::Script,
    )
    .unwrap();
    assert_eq!(execute(&compiler.compile(&ts).unwrap()), "4\n");
    let closure = SwcModule::parse(
        "capture.js",
        "function make(n) { return function() { return n; }; } print(make(3)());",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let bytes = compiler.compile(&closure).unwrap();
    assert_eq!(execute(&bytes), "3\n");
    let rebuilt = compiler.compile(&decompile(&bytes).unwrap()).unwrap();
    assert_eq!(execute(&rebuilt), "3\n");
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn mutable_sibling_and_multilevel_closures_preserve_environment_identity() {
    let compiler = compiler();
    for (source, expected) in [
        (
            "function make(start) { var value = start; return function(delta) { value = value + delta; return value; }; } var a = make(10); var b = make(100); print(a(1)); print(a(2)); print(b(5)); print(a(3));",
            "11\n13\n105\n16\n",
        ),
        (
            "function outer(a) { var x = a; return function middle(b) { var y = b; return function inner(c) { x = x + c; y = y + 1; return x + y; }; }; } var f = outer(10)(20); print(f(2)); print(f(3));",
            "33\n37\n",
        ),
        (
            "function pair(start) { var value = start; function one() { value = value + 1; return value; } function ten() { value = value + 10; return value; } return function(which) { if (which) return ten(); return one(); }; } var p = pair(0); print(p(0)); print(p(1)); print(p(0));",
            "1\n11\n12\n",
        ),
    ] {
        let module = SwcModule::parse(
            "closures.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .unwrap();
        let original = compiler.compile(&module).unwrap();
        assert_eq!(execute(&original), expected, "original: {source}");
        let rebuilt = compiler
            .compile(&decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}")))
            .unwrap();
        assert_eq!(execute(&rebuilt), expected, "rebuilt: {source}");
    }
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn decompilation_preserves_receiver_side_effects_and_nan_comparisons() {
    let compiler = compiler();
    for (source, expected) in [
        (
            "function check(x) { if (x < 1) return 10; return 20; } print(check('not a number'), check(0));",
            "20 10\n",
        ),
        (
            "var hits = 0; function bump() { hits = hits + 1; return hits; } print(bump() + bump(), hits);",
            "3 2\n",
        ),
        (
            "function method() { return this.value; } this.value = 7; this.method = method; method.call = 0; print(this.method());",
            "7\n",
        ),
        (
            "function f(x) { return x && 3; } print(f(0), f(1));",
            "0 3\n",
        ),
        (
            "function _g(x) { return x + 2; } function _mercury() { return _g(3); } print(_mercury(), _g.name);",
            "5 _g\n",
        ),
    ] {
        let module = SwcModule::parse(
            "semantics.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .unwrap();
        let original = compiler.compile(&module).unwrap();
        assert_eq!(execute(&original), expected);
        let generated = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
        assert_eq!(
            execute(&compiler.compile(&generated).unwrap()),
            expected,
            "{source}"
        );
    }
}

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
fn new_array_preserves_length_holes_and_mutation() {
    let compiler = compiler();
    let module = SwcModule::parse(
        "sparse-array.js",
        "var OriginalArray = Array; Array = function() { return 99; }; var empty = []; var sparse = [,,,]; print(empty.length, sparse.length, sparse instanceof OriginalArray, 0 in sparse, 2 in sparse); sparse[1] = 7; print(sparse.length, 0 in sparse, 1 in sparse, sparse[1]);",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&module).unwrap();
    assert_eq!(execute(&original), "0 3 true false false\n3 false true 7\n");
    let rebuilt = compiler.compile(&decompile(&original).unwrap()).unwrap();
    assert_eq!(execute(&rebuilt), "0 3 true false false\n3 false true 7\n");
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn populated_arrays_recover_buffered_and_dynamic_elements() {
    let compiler = compiler();
    for (source, expected) in [
        (
            "var flags = [null, true, false]; var numbers = [7, 3.5]; var strings = ['text', 'more']; var missing = [void 0]; print(flags.length, flags[0], flags[1], flags[2], numbers[0], numbers[1], strings[0], strings[1], missing[0], 0 in missing);",
            "3 null true false 7 3.5 text more undefined true\n",
        ),
        (
            "var hits = 0; Array.prototype.__defineSetter__('0', function(value) { hits = hits + 1; }); function wrap(value) { return [value, 2]; } var dynamic = wrap(42); print(hits, dynamic.hasOwnProperty('0'), dynamic[0], dynamic[1]);",
            "0 true 42 2\n",
        ),
        (
            "function pair(start) { var value = start; function one() { value = value + 1; return value; } function ten() { value = value + 10; return value; } return [one, ten]; } var p = pair(0); print(p[0](), p[1](), p[0]());",
            "1 11 12\n",
        ),
    ] {
        let module = SwcModule::parse(
            "populated-array.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .unwrap();
        let original = compiler.compile(&module).unwrap();
        assert_eq!(execute(&original), expected, "original: {source}");
        let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
        let rebuilt = compiler.compile(&recovered).unwrap();
        assert_eq!(execute(&rebuilt), expected, "rebuilt: {source}");
    }
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn buffered_objects_recover_static_and_dynamic_properties() {
    let compiler = compiler();
    for (source, expected) in [
        (
            "var buffered = { alpha: null, beta: true, gamma: false, integer: 7, double: 3.5, text: 'value' }; print(buffered.alpha, buffered.beta, buffered.gamma, buffered.integer, buffered.double, buffered.text, Object.keys(buffered).join(','));",
            "null true false 7 3.5 value alpha,beta,gamma,integer,double,text\n",
        ),
        (
            "var hits = 0; Object.prototype.__defineSetter__('dynamic', function(value) { hits = hits + 1; }); function make(value) { return { fixed: 1, dynamic: value }; } var object = make(42); var descriptor = Object.getOwnPropertyDescriptor(object, 'dynamic'); print(hits, object.hasOwnProperty('dynamic'), object.dynamic, descriptor.enumerable, descriptor.writable, descriptor.configurable);",
            "0 true 42 true true true\n",
        ),
        (
            "var key = 'computed'; var object = { 2: 'two', 1: 'one', fixed: 2, [key]: 3, a: 1, a: 4, ['__proto__']: 7 }; print(Object.keys(object).join(','), object[1], object[2], object.computed, object.a, object.hasOwnProperty('__proto__'), object.__proto__);",
            "1,2,fixed,computed,a,__proto__ one two 3 4 true 7\n",
        ),
    ] {
        let module = SwcModule::parse(
            "buffered-object.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .unwrap();
        let original = compiler.compile(&module).unwrap();
        assert_eq!(execute(&original), expected, "original: {source}");
        let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
        let rebuilt = compiler.compile(&recovered).unwrap();
        assert_eq!(execute(&rebuilt), expected, "rebuilt: {source}");
    }
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn custom_object_prototypes_preserve_parent_selection() {
    let compiler = compiler();
    for (source, expected) in [
        (
            "var parent = { inherited: 7 }; var object = { __proto__: parent, own: 3 }; var descriptor = Object.getOwnPropertyDescriptor(object, 'own'); print(parent.isPrototypeOf(object), object.inherited, object.own, object.hasOwnProperty('__proto__'), descriptor.enumerable, descriptor.writable, descriptor.configurable);",
            "true 7 3 false true true true\n",
        ),
        (
            "var object = { __proto__: null, own: 4 }; print(object.toString === undefined, object.own, object.__proto__ === undefined);",
            "true 4 true\n",
        ),
        (
            "var object = { __proto__: 9, own: 5 }; print(object.toString !== undefined, object.own, object.hasOwnProperty('__proto__'));",
            "true 5 false\n",
        ),
    ] {
        let module = SwcModule::parse(
            "object-parent.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .unwrap();
        let original = compiler.compile(&module).unwrap();
        assert_eq!(execute(&original), expected, "original: {source}");
        let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
        let rebuilt = compiler.compile(&recovered).unwrap();
        assert_eq!(execute(&rebuilt), expected, "rebuilt: {source}");
    }
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn integer_switch_tables_recover_all_targets_and_default() {
    let source = "function choose(value) { switch (value) { case 2: return 'two'; case 3: case 4: return 'three-four'; case 6: return 'six'; default: return 'other'; } } print(choose(2), choose(3), choose(4), choose(5), choose(6), choose(7), choose('3'), choose(3.5));";
    let expected = "two three-four three-four other six other other other\n";
    let compiler = compiler();
    let module = SwcModule::parse(
        "integer-switch.js",
        source,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&module).unwrap();
    assert_eq!(execute(&original), expected);
    let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
    let rebuilt = compiler.compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected);
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn exception_handlers_recover_catches_calls_and_finally() {
    let source = "function fail() { throw 7; } function called() { try { return fail(); } catch (error) { return error + 1; } } function nested(flag) { var out = ''; try { try { if (flag) throw 'x'; out = out + 'a'; } catch (error) { out = out + 'inner' + error; throw 'y'; } finally { out = out + 'f'; } } catch (error) { out = out + 'outer' + error; } return out; } print(called(), nested(false), nested(true));";
    let expected = "8 af innerxfoutery\n";
    let compiler = compiler();
    let module = SwcModule::parse(
        "exceptions.js",
        source,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&module).unwrap();
    assert_eq!(execute(&original), expected);
    let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
    let rebuilt = compiler.compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected);
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn regexp_and_bigint_constants_recover_runtime_values() {
    let source = "var regexp = /a+b/gi; var positive = 123456789012345678901234567890n; var negative = -98765432109876543210987654321n; print(regexp.test('xxAAAb'), regexp.test('ccc'), String(positive + 10n), String(negative));";
    let expected = "true false 123456789012345678901234567900 -98765432109876543210987654321\n";
    let compiler = compiler();
    let module = SwcModule::parse(
        "runtime-data.js",
        source,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&module).unwrap();
    assert_eq!(execute(&original), expected);
    let recovered = decompile(&original).unwrap_or_else(|err| panic!("{source}: {err}"));
    let rebuilt = compiler.compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected);
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

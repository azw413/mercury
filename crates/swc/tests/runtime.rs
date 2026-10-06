use mercury_binary::{
    build_minimal_module, decode_raw_module, parse_hbc_container_with_spec, DecodedInstruction,
    DecodedOperand, MinimalFunction, MinimalModule,
};
use mercury_spec_builtin::load_spec;
use mercury_swc::{
    ast::Number,
    decompile,
    visit::{VisitMut, VisitMutWith},
    HermesCompiler, SourceKind, SourceLanguage, SwcModule,
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
    .arg("-Xes6-class")
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
fn execute_failure(bytes: &[u8]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.hbc");
    fs::write(&path, bytes).unwrap();
    let output = Command::new(
        std::env::var_os("HERMES_BIN").expect("set HERMES_BIN to a version-96 runtime"),
    )
    .arg("-Xes6-class")
    .arg("-b")
    .arg(path)
    .output()
    .unwrap();
    assert!(output.status.code().is_some_and(|code| code != 0));
    String::from_utf8(output.stderr).unwrap()
}
fn assert_runtime_roundtrip(name: &str, source: &str, expected: &str) {
    let compiler = compiler();
    let module =
        SwcModule::parse(name, source, SourceLanguage::JavaScript, SourceKind::Script).unwrap();
    let original = compiler.compile(&module).unwrap();
    assert_eq!(execute(&original), expected, "original source");
    let recovered = decompile(&original).unwrap();
    let rebuilt = compiler.compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected, "decompiled source");
}
fn instruction(name: &str, operands: Vec<DecodedOperand>) -> DecodedInstruction {
    let spec = load_spec(96).unwrap();
    let opcode = spec
        .bytecode
        .instructions
        .iter()
        .find(|instruction| instruction.name == name)
        .unwrap()
        .opcode;
    DecodedInstruction {
        offset: 0,
        opcode,
        name: name.into(),
        operands,
        size: 0,
    }
}
fn build_test_module(strings: Vec<String>, functions: Vec<MinimalFunction>) -> Vec<u8> {
    let spec = load_spec(96).unwrap();
    build_minimal_module(
        &MinimalModule {
            version: 96,
            global_code_index: 0,
            strings,
            string_kinds: vec![],
            literal_value_buffer: vec![],
            object_key_buffer: vec![],
            object_value_buffer: vec![],
            functions,
        },
        &spec.bytecode,
    )
    .unwrap()
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
fn generator_frames_support_next_throw_return_closures_and_delegation() {
    assert_runtime_roundtrip(
        "generator-suspension.js",
        include_str!("fixtures/generator_suspension.js"),
        "first-1 4 false\nsecond-1 10 false\nfirst-2 7 false\nfinally 7\nfirst-3 8 true\nfirst-4 undefined true\nfinally 10\nsecond-return 44 true\nsecond-after undefined true\niterator true\nthrow-1 ready false\nthrow-2 caught:boom false\nthrow-3 finished true\ndelegate-1 1 false\ndelegate-2 delegated-catch:x false\ninner-finally\ndelegate-3 outer:7 true\ndelegate-4 undefined true\nreturn-1 1 false\ninner-finally\nreturn-2 9 true\nreturn-3 undefined true\nbefore-start-return 5 true\nbefore-start-catch before-start-throw\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn long_generator_suspension_roundtrips() {
    let zeros = std::iter::repeat_n("0", 260).collect::<Vec<_>>().join(",");
    let source = format!(
        "function* values() {{ yield* [1]; [].push({zeros}); }} var iterator = values(); print(iterator.next().value, iterator.next().done);"
    );
    let compiler = compiler();
    let module = SwcModule::parse(
        "save-generator-long.js",
        &source,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let original = compiler.compile(&module).unwrap();
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&original, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &original, &spec.bytecode).unwrap();
    assert!(raw.functions.iter().any(|function| {
        function
            .instructions
            .iter()
            .any(|instruction| instruction.name == "SaveGeneratorLong")
    }));
    assert_eq!(execute(&original), "1 true\n");
    let rebuilt = compiler.compile(&decompile(&original).unwrap()).unwrap();
    assert_eq!(execute(&rebuilt), "1 true\n");
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn async_frames_support_fulfilled_and_rejected_awaits_with_captures_and_receivers() {
    assert_runtime_roundtrip(
        "async-suspension.js",
        include_str!("fixtures/async_suspension.js"),
        "rejected caught:no\nreceiver 14\nresolved 7\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn constructors_preserve_receivers_returns_prototypes_and_new_target() {
    assert_runtime_roundtrip(
        "constructors.js",
        include_str!("fixtures/constructors.js"),
        "3 4 6 true true 7 6 true true false\narrow true\nnew-target true\nobject-prototype 2 1 0 8 false\nnew-target true\nprimitive-prototype 2 1 0 8 true\nnot-constructor 1 true\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn classes_preserve_inheritance_methods_accessors_static_methods_and_super_calls() {
    assert_runtime_roundtrip(
        "classes.js",
        include_str!("fixtures/classes.js"),
        "7 6 7 13 true true method total\n3 make\n9\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn construct_long_preserves_more_than_255_arguments() {
    let parameters = (0..260)
        .map(|index| format!("p{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let arguments = (0..260)
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "function Many({parameters}) {{ this.first = p0; this.last = p259; }} var value = new Many({arguments}); print(value.first, value.last);"
    );
    assert_runtime_roundtrip("construct-long.js", &source, "0 259\n");
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn common_opcodes_preserve_coercion_arguments_and_accessor_semantics() {
    assert_runtime_roundtrip(
        "common-opcodes.js",
        include_str!("fixtures/common_opcodes.js"),
        "5 3 7 8 3.5 1 9 true true undefined undefined\n5 3 4 5\nfalse 1\nstrict-delete true 1\narguments 3 7\nreturned-arguments 2 3\nargument-aliasing 1 2\naccessor 3 true true get value set value\nset 9\nnon-finite true Infinity -Infinity -Infinity\nbuffered-non-finite true Infinity -Infinity true Infinity -Infinity\nexponent 8 base,power\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn remaining_vm_opcodes_preserve_environments_calls_tdz_and_global_writes() {
    assert_runtime_roundtrip(
        "try-put.js",
        "\"use strict\"; try { missing = 7; print('bad'); } catch (error) { print(error.name); } this.existing = 1; existing = 9; print(this.existing);",
        "ReferenceError\n9\n",
    );

    use DecodedOperand::{U16, U32, U8};
    let original = build_test_module(
        vec![],
        vec![
            MinimalFunction {
                name: "global".into(),
                param_count: 1,
                frame_size: 14,
                environment_size: 0,
                instructions: vec![
                    instruction("Debugger", vec![]),
                    instruction("AsyncBreakCheck", vec![]),
                    instruction("ProfilePoint", vec![U16(0)]),
                    instruction("CreateEnvironment", vec![U8(0)]),
                    instruction("CreateInnerEnvironment", vec![U8(1), U8(0), U32(1)]),
                    instruction("LoadConstUInt8", vec![U8(2), U8(9)]),
                    instruction("StoreToEnvironment", vec![U8(1), U8(0), U8(2)]),
                    instruction("CreateClosure", vec![U8(3), U8(1), U16(1)]),
                    instruction("LoadConstUndefined", vec![U8(4)]),
                    instruction("Call1", vec![U8(2), U8(3), U8(4)]),
                    instruction("CoerceThisNS", vec![U8(3), U8(4)]),
                    instruction("GetGlobalObject", vec![U8(5)]),
                    instruction("StrictEq", vec![U8(3), U8(3), U8(5)]),
                    instruction("ThrowIfEmpty", vec![U8(4), U8(2)]),
                    instruction("LoadConstEmpty", vec![U8(6)]),
                    instruction("Add", vec![U8(5), U8(4), U8(3)]),
                    instruction("Throw", vec![U8(5)]),
                ],
            },
            MinimalFunction {
                name: "captured".into(),
                param_count: 1,
                frame_size: 1,
                environment_size: 0,
                instructions: vec![
                    instruction("GetEnvironment", vec![U8(0), U8(0)]),
                    instruction("LoadFromEnvironment", vec![U8(0), U8(0), U8(0)]),
                    instruction("Ret", vec![U8(0)]),
                ],
            },
        ],
    );
    assert!(execute_failure(&original).contains("Uncaught 10"));
    let rebuilt = compiler().compile(&decompile(&original).unwrap()).unwrap();
    assert!(execute_failure(&rebuilt).contains("Uncaught 10"));

    for direct_call in [
        instruction("CallDirect", vec![U8(0), U8(2), U16(1)]),
        instruction("CallDirectLongIndex", vec![U8(0), U8(2), U32(1)]),
    ] {
        let direct = build_test_module(
            vec![],
            vec![
                MinimalFunction {
                    name: "global".into(),
                    param_count: 1,
                    frame_size: 10,
                    environment_size: 0,
                    instructions: vec![
                        instruction("LoadConstUndefined", vec![U8(3)]),
                        instruction("LoadConstUInt8", vec![U8(2), U8(42)]),
                        direct_call,
                        instruction("Throw", vec![U8(0)]),
                    ],
                },
                MinimalFunction {
                    name: "direct".into(),
                    param_count: 2,
                    frame_size: 1,
                    environment_size: 0,
                    instructions: vec![
                        instruction("LoadParam", vec![U8(0), U8(1)]),
                        instruction("Ret", vec![U8(0)]),
                    ],
                },
            ],
        );
        assert!(execute_failure(&direct).contains("Uncaught 42"));
        let rebuilt = compiler().compile(&decompile(&direct).unwrap()).unwrap();
        assert!(execute_failure(&rebuilt).contains("Uncaught 42"));
    }

    let tdz = build_test_module(
        vec![],
        vec![MinimalFunction {
            name: "global".into(),
            param_count: 1,
            frame_size: 2,
            environment_size: 0,
            instructions: vec![
                instruction("LoadConstEmpty", vec![U8(0)]),
                instruction("ThrowIfEmpty", vec![U8(1), U8(0)]),
                instruction("Ret", vec![U8(1)]),
            ],
        }],
    );
    assert!(execute_failure(&tdz).contains("ReferenceError"));
    let rebuilt = compiler().compile(&decompile(&tdz).unwrap()).unwrap();
    assert!(execute_failure(&rebuilt).contains("ReferenceError"));
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn typed_arithmetic_and_memory_opcodes_preserve_i32_and_view_semantics() {
    use DecodedOperand::{I32, U16, U8};
    let original = build_test_module(
        vec![
            "ArrayBuffer".into(),
            "Int8Array".into(),
            "prototype".into(),
            "print".into(),
            "arithmetic".into(),
            "loads".into(),
            "stores".into(),
        ],
        vec![MinimalFunction {
            name: "global".into(),
            param_count: 1,
            frame_size: 40,
            environment_size: 0,
            instructions: vec![
                instruction("LoadConstInt", vec![U8(0), I32(2_147_483_647)]),
                instruction("LoadConstUInt8", vec![U8(1), U8(1)]),
                instruction("Add32", vec![U8(6), U8(0), U8(1)]),
                instruction("LoadConstInt", vec![U8(0), I32(i32::MIN)]),
                instruction("Sub32", vec![U8(7), U8(0), U8(1)]),
                instruction("LoadConstInt", vec![U8(0), I32(2_147_483_647)]),
                instruction("LoadConstUInt8", vec![U8(2), U8(2)]),
                instruction("Mul32", vec![U8(8), U8(0), U8(2)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(43)]),
                instruction("LoadConstInt", vec![U8(1), I32(-7)]),
                instruction("Divi32", vec![U8(9), U8(0), U8(1)]),
                instruction("LoadConstInt", vec![U8(0), I32(-2)]),
                instruction("Divu32", vec![U8(10), U8(0), U8(2)]),
                instruction("GetGlobalObject", vec![U8(0)]),
                instruction("TryGetById", vec![U8(11), U8(0), U8(0), U16(3)]),
                instruction("LoadConstUndefined", vec![U8(33)]),
                instruction("LoadConstString", vec![U8(32), U16(4)]),
                instruction("Mov", vec![U8(31), U8(6)]),
                instruction("Mov", vec![U8(30), U8(7)]),
                instruction("Mov", vec![U8(29), U8(8)]),
                instruction("Mov", vec![U8(28), U8(9)]),
                instruction("Mov", vec![U8(27), U8(10)]),
                instruction("Call", vec![U8(0), U8(11), U8(7)]),
                instruction("GetGlobalObject", vec![U8(0)]),
                instruction("TryGetById", vec![U8(1), U8(0), U8(1), U16(0)]),
                instruction("GetByIdShort", vec![U8(2), U8(1), U8(2), U8(2)]),
                instruction("CreateThis", vec![U8(2), U8(2), U8(1)]),
                instruction("LoadConstUInt8", vec![U8(3), U8(32)]),
                instruction("Mov", vec![U8(33), U8(2)]),
                instruction("Mov", vec![U8(32), U8(3)]),
                instruction("Construct", vec![U8(4), U8(1), U8(2)]),
                instruction("SelectObject", vec![U8(4), U8(2), U8(4)]),
                instruction("GetGlobalObject", vec![U8(0)]),
                instruction("TryGetById", vec![U8(1), U8(0), U8(3), U16(1)]),
                instruction("GetByIdShort", vec![U8(2), U8(1), U8(4), U8(2)]),
                instruction("CreateThis", vec![U8(2), U8(2), U8(1)]),
                instruction("Mov", vec![U8(33), U8(2)]),
                instruction("Mov", vec![U8(32), U8(4)]),
                instruction("Construct", vec![U8(5), U8(1), U8(2)]),
                instruction("SelectObject", vec![U8(5), U8(2), U8(5)]),
                instruction("LoadConstZero", vec![U8(0)]),
                instruction("LoadConstInt", vec![U8(1), I32(-66_052)]),
                instruction("Store32", vec![U8(5), U8(0), U8(1)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(3)]),
                instruction("Loadi8", vec![U8(6), U8(5), U8(0)]),
                instruction("Loadu8", vec![U8(7), U8(5), U8(0)]),
                instruction("Loadi16", vec![U8(8), U8(5), U8(0)]),
                instruction("Loadu16", vec![U8(9), U8(5), U8(0)]),
                instruction("LoadConstZero", vec![U8(0)]),
                instruction("Loadi32", vec![U8(10), U8(5), U8(0)]),
                instruction("Loadu32", vec![U8(11), U8(5), U8(0)]),
                instruction("GetGlobalObject", vec![U8(0)]),
                instruction("TryGetById", vec![U8(12), U8(0), U8(5), U16(3)]),
                instruction("LoadConstUndefined", vec![U8(33)]),
                instruction("LoadConstString", vec![U8(32), U16(5)]),
                instruction("Mov", vec![U8(31), U8(6)]),
                instruction("Mov", vec![U8(30), U8(7)]),
                instruction("Mov", vec![U8(29), U8(8)]),
                instruction("Mov", vec![U8(28), U8(9)]),
                instruction("Mov", vec![U8(27), U8(10)]),
                instruction("Mov", vec![U8(26), U8(11)]),
                instruction("Call", vec![U8(0), U8(12), U8(8)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(4)]),
                instruction("LoadConstUInt8", vec![U8(1), U8(255)]),
                instruction("Store8", vec![U8(5), U8(0), U8(1)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(7)]),
                instruction("LoadConstInt", vec![U8(1), I32(33_059)]),
                instruction("Store16", vec![U8(5), U8(0), U8(1)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(11)]),
                instruction("LoadConstInt", vec![U8(1), I32(-2_147_483_647)]),
                instruction("Store32", vec![U8(5), U8(0), U8(1)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(4)]),
                instruction("Loadi8", vec![U8(6), U8(5), U8(0)]),
                instruction("Loadu8", vec![U8(7), U8(5), U8(0)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(7)]),
                instruction("Loadi16", vec![U8(8), U8(5), U8(0)]),
                instruction("Loadu16", vec![U8(9), U8(5), U8(0)]),
                instruction("LoadConstUInt8", vec![U8(0), U8(11)]),
                instruction("Loadi32", vec![U8(10), U8(5), U8(0)]),
                instruction("Loadu32", vec![U8(11), U8(5), U8(0)]),
                instruction("GetGlobalObject", vec![U8(0)]),
                instruction("TryGetById", vec![U8(12), U8(0), U8(6), U16(3)]),
                instruction("LoadConstUndefined", vec![U8(33)]),
                instruction("LoadConstString", vec![U8(32), U16(6)]),
                instruction("Mov", vec![U8(31), U8(6)]),
                instruction("Mov", vec![U8(30), U8(7)]),
                instruction("Mov", vec![U8(29), U8(8)]),
                instruction("Mov", vec![U8(28), U8(9)]),
                instruction("Mov", vec![U8(27), U8(10)]),
                instruction("Mov", vec![U8(26), U8(11)]),
                instruction("Call", vec![U8(0), U8(12), U8(8)]),
                instruction("LoadConstUndefined", vec![U8(0)]),
                instruction("Ret", vec![U8(0)]),
            ],
        }],
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&original, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &original, &spec.bytecode).unwrap();
    for name in [
        "Add32", "Sub32", "Mul32", "Divi32", "Divu32", "Loadi8", "Loadu8", "Loadi16", "Loadu16",
        "Loadi32", "Loadu32", "Store8", "Store16", "Store32",
    ] {
        assert!(
            raw.functions
                .iter()
                .flat_map(|function| &function.instructions)
                .any(|instruction| instruction.name == name),
            "fixture did not produce {name}"
        );
    }
    let expected = "arithmetic -2147483648 2147483647 -2 -6 2147483647\nloads -1 255 -2 65534 -66052 -66052\nstores -1 255 -32477 33059 -2147483647 -2147483647\n";
    // HBC builds without HERMES_RUN_WASM abort when executing these opcodes,
    // even though the version-96 format includes them. Execute the portable
    // reconstruction after asserting that the source HBC contains every op.
    let recovered = decompile(&original).unwrap();
    let rebuilt = compiler().compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected);
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn property_and_value_iteration_preserve_mutation_and_close_semantics() {
    assert_runtime_roundtrip(
        "iteration.js",
        include_str!("fixtures/iteration.js"),
        "for-in first,shadowed,inherited\nfor-in-values 0,1 0\narray-iterator 1,undefined,3,4\niterator-close next,value:1,return\ninvalid-next true\nbreak-close close\nthrow-close body\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn object_spread_and_rest_preserve_keys_descriptors_and_proxy_order() {
    assert_runtime_roundtrip(
        "object-spread.js",
        include_str!("fixtures/object_spread.js"),
        "spread 0 5 4 2 undefined undefined 1 true true true\nrest 1 undefined 4 2 undefined undefined 2\nproxy 7 undefined keys,descriptor:visible,get:visible,descriptor:skipped\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn utf16_strings_preserve_paired_and_unpaired_surrogates() {
    assert_runtime_roundtrip(
        "utf16-strings.js",
        include_str!("fixtures/utf16_strings.js"),
        "units 1 d800 1 dfff 2 d83d de00 3 d800 41 dfff\nbuffered dfff 2 3 dfff 2 3 d800\nproperty true true true false\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn direct_eval_preserves_global_scope_strictness_and_completion() {
    assert_runtime_roundtrip(
        "direct-eval.js",
        include_str!("fixtures/direct_eval.js"),
        "values 7 9 8 ReferenceError undefined true\nsyntax SyntaxError\n",
    );
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn committed_hex_and_box2d_fixtures_recompile_with_identical_output() {
    let compiler = compiler();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test");
    for name in ["hex.hbc", "box2d.hbc"] {
        let original = fs::read(fixtures.join(name)).unwrap();
        let expected = execute(&original);
        let recovered = decompile(&original).unwrap_or_else(|error| panic!("{name}: {error}"));
        let rebuilt = compiler.compile(&recovered).unwrap();
        assert_eq!(execute(&rebuilt), expected, "{name}");
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

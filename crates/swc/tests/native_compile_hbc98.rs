use std::{fs, process::Command};

use mercury_hbc::binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_hbc::ir::{RawFunction, RawOperand};
use mercury_hbc::spec_builtin::load_spec;
use mercury_hbc::{HbcCompiler, SourceKind, SourceLanguage, SwcModule};

fn compile(source: &str) -> Vec<u8> {
    let module = SwcModule::parse(
        "input.js",
        source,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    HbcCompiler::new(98).compile(&module).unwrap()
}

fn decode(
    bytes: &[u8],
) -> (
    mercury_hbc::binary::HbcContainer,
    mercury_hbc::ir::RawModule,
) {
    let spec = load_spec(98).unwrap();
    let container = parse_hbc_container_with_spec(bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, bytes, &spec.bytecode).unwrap();
    (container, raw)
}

fn instruction_names(function: &RawFunction) -> Vec<&str> {
    function
        .instructions
        .iter()
        .map(|instruction| instruction.name.as_str())
        .collect()
}

fn builtin_ids(function: &RawFunction) -> Vec<u8> {
    function
        .instructions
        .iter()
        .filter(|instruction| instruction.name == "CallBuiltin")
        .filter_map(|instruction| match instruction.operands.get(1) {
            Some(RawOperand::U8(value)) => Some(*value),
            _ => None,
        })
        .collect()
}

#[test]
fn compiles_and_decodes_a_minimal_hbc98_script() {
    let bytes = compile("print(40 + 2);");
    let (container, raw) = decode(&bytes);

    assert_eq!(container.header.version, 98);
    assert_eq!(raw.functions.len(), 1);
    assert!(instruction_names(&raw.functions[0]).contains(&"Call2"));
}

#[test]
fn emits_strict_and_loose_property_and_arguments_opcodes() {
    let bytes = compile(
        r#"
        var object = {};
        object.loose = 1;
        object["comp" + "uted"] = 2;
        function strict(value) {
            "use strict";
            var target = {};
            target.strict = value;
            target["comp" + "uted"] = value;
            return arguments[0] + target.strict + target.computed;
        }
        function looseArguments(value) { return arguments[0]; }
        print(strict(3));
        print(looseArguments(4));
        "#,
    );
    let (_, raw) = decode(&bytes);
    let global_names = instruction_names(&raw.functions[0]);
    assert!(global_names.contains(&"PutByIdLoose"));
    assert!(global_names.contains(&"PutByValLoose"));

    let strict = raw
        .functions
        .iter()
        .find(|function| instruction_names(function).contains(&"PutByIdStrict"))
        .expect("strict function");
    let strict_names = instruction_names(strict);
    assert!(strict_names.contains(&"PutByValStrict"));
    assert!(strict_names.contains(&"ReifyArgumentsStrict"));

    let loose = raw
        .functions
        .iter()
        .find(|function| instruction_names(function).contains(&"ReifyArgumentsLoose"))
        .expect("loose arguments function");
    assert!(!instruction_names(loose).contains(&"ReifyArgumentsStrict"));
}

#[test]
fn uses_hbc98_cache_slots_and_disables_caching_at_255() {
    let mut source = String::from("var object = {};\n");
    for index in 0..300 {
        source.push_str(&format!("object.p{index} = {index};\n"));
    }
    source.push_str("print(object.p0 + object.p254 + object.p299);\n");
    let bytes = compile(&source);
    let (container, raw) = decode(&bytes);
    let cache_indices = raw.functions[0]
        .instructions
        .iter()
        .filter(|instruction| instruction.name == "PutByIdLoose")
        .filter_map(|instruction| instruction.operands.get(2))
        .filter_map(|operand| match operand {
            RawOperand::U8(value) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(cache_indices[0], 0);
    assert!(cache_indices.contains(&254));
    assert!(cache_indices.contains(&255));
    assert_eq!(container.function_headers[0].highest_write_cache_index, 255);
}

#[test]
fn uses_hbc98_private_builtin_ids() {
    let bytes = compile(
        r#"
        print(2 ** 5);
        var match = /(?<year>\d{4})/.exec("2026");
        print(match.groups.year);
        print([0, ...[1, 2]].length);
        function sum3(a, b, c) { return a + b + c; }
        print(sum3(...[1, 2, 3]));
        "#,
    );
    let (_, raw) = decode(&bytes);
    let ids = raw
        .functions
        .iter()
        .flat_map(|function| builtin_ids(function))
        .collect::<Vec<_>>();

    assert!(ids.contains(&48), "missing array-spread builtin: {ids:?}");
    assert!(ids.contains(&49), "missing apply builtin: {ids:?}");
    assert!(ids.contains(&53), "missing exponentiation builtin: {ids:?}");
    assert!(ids.contains(&54), "missing named-regexp builtin: {ids:?}");
    assert!(!ids.contains(&51));
    assert!(!ids.contains(&52));
}

#[test]
fn lowers_large_calls_through_apply_for_hbc98() {
    let arguments = (0..255).map(|_| "1").collect::<Vec<_>>().join(",");
    let source = format!(
        "function sum() {{ var total = 0; for (var i = 0; i < arguments.length; i++) total += arguments[i]; return total; }} print(sum({arguments})); function Ctor() {{ this.value = arguments.length; }} print(new Ctor({arguments}).value);"
    );
    let bytes = compile(&source);
    let (_, raw) = decode(&bytes);
    let global_names = instruction_names(&raw.functions[0]);

    assert!(builtin_ids(&raw.functions[0]).contains(&49));
    assert!(
        !global_names
            .iter()
            .any(|name| matches!(*name, "Call" | "CallLong" | "Construct"))
    );
}

#[test]
#[ignore = "requires HERMES98_BIN pointing to an HBC 98 runtime"]
fn hbc98_native_compilation_executes_correctly() {
    let source = r#"
        print(40 + 2);
        var object = {};
        object.loose = 1;
        object["comp" + "uted"] = 2;
        function strict(value) {
            "use strict";
            var target = {};
            target.strict = value;
            target["comp" + "uted"] = value;
            return arguments[0] + target.strict + target.computed;
        }
        function looseArguments(value) { return arguments[0]; }
        print(strict(3));
        print(looseArguments(4));
        print(2 ** 5);
        var match = /(?<year>\d{4})/.exec("2026");
        print(match.groups.year);
        function sum3(a, b, c) { return a + b + c; }
        print(sum3(...[1, 2, 3]));
        function Point(x, y) { this.x = x; this.y = y; }
        var point = new Point(...[4, 5]);
        print(point.x + point.y);
    "#;
    assert_eq!(execute(compile(source)), "42\n9\n4\n32\n2026\n6\n9\n");
}

#[test]
#[ignore = "requires HERMES98_BIN pointing to an HBC 98 runtime"]
fn hbc98_builtin_and_constructor_calls_execute_correctly() {
    assert_eq!(execute(compile("var two = 2; print(two ** 5);")), "32\n");
    assert_eq!(
        execute(compile(
            r#"var match = /(?<year>\d{4})/.exec("2026"); print(match.groups.year);"#
        )),
        "2026\n"
    );
    assert_eq!(
        execute(compile("print([0, ...[1, 2]].join(','));")),
        "0,1,2\n"
    );
    assert_eq!(
        execute(compile(
            "function sum3(a, b, c) { return a + b + c; } print(sum3(1, 2, 3));"
        )),
        "6\n"
    );
    assert_eq!(
        execute(compile(
            "function sum3(a, b, c) { return a + b + c; } print(sum3(...[1, 2, 3]));"
        )),
        "6\n"
    );
    assert_eq!(
        execute(compile(
            "function Point(x, y) { this.x = x; this.y = y; } var point = new Point(4, 5); print(point.x + point.y);"
        )),
        "9\n"
    );
    assert_eq!(
        execute(compile(
            "function Point(x, y) { this.x = x; this.y = y; } var point = new Point(...[4, 5]); print(point.x + point.y);"
        )),
        "9\n"
    );
}

#[test]
#[ignore = "requires HERMES98_BIN pointing to an HBC 98 runtime"]
fn hbc98_environments_deletion_and_arrays_execute_correctly() {
    let source = r#"
        function outer(x) {
            let captured = x;
            { let nested = 2; captured += nested; }
            return function(y) { return captured + y; };
        }
        var closure = outer(3);
        print(closure(4));
        var object = {keep: 1, remove: 2};
        var key = "remove";
        print(delete object[key]);
        print(Object.keys(object).join(","));
        print([1, 2, 3].join(""));
    "#;
    let bytes = compile(source);
    let (_, raw) = decode(&bytes);
    let names = raw
        .functions
        .iter()
        .flat_map(|function| instruction_names(function))
        .collect::<Vec<_>>();
    assert!(names.contains(&"CreateTopLevelEnvironment"));
    assert!(names.contains(&"CreateFunctionEnvironment"));
    assert!(names.contains(&"CreateEnvironment"));
    assert!(names.contains(&"GetParentEnvironment"));
    assert!(names.contains(&"DelByVal"));
    assert!(names.contains(&"DefineOwnInDenseArray"));

    assert_eq!(execute(bytes), "9\ntrue\nkeep\n123\n");
}

#[test]
#[ignore = "requires HERMES98_BIN pointing to an HBC 98 runtime"]
fn hbc98_cache_exhaustion_and_large_calls_execute_correctly() {
    let mut cache_source = String::from("var object = {};\n");
    for index in 0..300 {
        cache_source.push_str(&format!("object.p{index} = {index};\n"));
    }
    cache_source.push_str("print(object.p0 + object.p254 + object.p299);\n");
    assert_eq!(execute(compile(&cache_source)), "553\n");

    let arguments = (0..255).map(|_| "1").collect::<Vec<_>>().join(",");
    let source = format!(
        "function sum() {{ var total = 0; for (var i = 0; i < arguments.length; i++) total += arguments[i]; return total; }} print(sum({arguments})); function Ctor() {{ this.value = arguments.length; }} print(new Ctor({arguments}).value);"
    );
    assert_eq!(execute(compile(&source)), "255\n255\n");
}

fn execute(bytes: Vec<u8>) -> String {
    let path = std::env::temp_dir().join(format!(
        "mercury-native-hbc98-{}-{}.hbc",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, bytes).unwrap();
    let hermes = std::env::var_os("HERMES98_BIN").expect("HERMES98_BIN must point to Hermes 98");
    let output = Command::new(hermes).arg(&path).output().unwrap();
    let _ = fs::remove_file(path);
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

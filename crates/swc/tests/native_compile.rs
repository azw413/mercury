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
        "switch (value) { case 1: print(1); }",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let error = HbcCompiler::new(96).compile(&module).unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported: switch statements are not supported by native compilation yet"
    );
}

#[test]
fn resolves_symbolic_control_flow_into_hbc_branches() {
    let bytes = compile(
        "var total = 0; for (var i = 0; i < 4; i = i + 1) { if (i === 2) continue; total = total + i; } print(total === 4 ? 'yes' : 'no');",
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

    assert!(names.contains(&"JmpFalseLong"));
    assert!(names.contains(&"JmpLong"));
    assert!(names.contains(&"StrictEq"));
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn compiles_updates_literals_and_construction_opcodes() {
    let bytes = compile(
        "var i = 1; i++; i += 2; var a = [i, , 3]; var o = {value: a[0], ['x']: 4}; o.x *= 2; var d = new Date(1); print(d.getTime());",
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

    for expected in [
        "Inc",
        "Add",
        "NewArray",
        "PutOwnByIndex",
        "NewObject",
        "PutOwnByVal",
        "CreateThis",
        "Construct",
        "SelectObject",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn rejects_object_prototype_setters_until_parent_construction_is_supported() {
    let module = SwcModule::parse(
        "input.js",
        "var object = { __proto__: null };",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let error = HbcCompiler::new(96).compile(&module).unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported: object-literal `__proto__` setters are not supported by native compilation yet"
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
    assert_eq!(execute(bytes), "42\n42\n7\nundefined\n");
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_control_flow_and_short_circuiting_execute() {
    let bytes = compile(
        r#"
        var total = 0;
        var i = 0;
        while (i < 6) {
            i = i + 1;
            if (i === 2) continue;
            if (i === 5) break;
            total = total + i;
        }
        if (total === 8) print("while", total); else print("bad", total);
        var j = 0;
        do { total = total + 1; j = j + 1; } while (j < 2);
        for (var k = 0; k < 3; k = k + 1) total = total + k;
        print("total", total);
        print(false && missing);
        print(true || missing);
        print(null ?? 9);
        print(0 ?? 9);
        print(total === 13 ? "yes" : "no");
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        "while 8\ntotal 13\nfalse\ntrue\n9\n0\nyes\n"
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_updates_literals_and_constructors_execute() {
    let bytes = compile(
        r#"
        var i = 1;
        print(i++, i, ++i);
        i += 4;
        i *= 2;
        print(i);

        var array = [10, , 30];
        var keyIndex = 0;
        var old = array[keyIndex++]++;
        var changed = array[0] += 5;
        print(old, changed, keyIndex);
        print(array.length, 1 in array, array[0]);

        var key = "x";
        var object = {a: 1, [key]: 2, a: 3};
        object[key] *= 4;
        print(object.a, object.x, Object.keys(object).join(","));

        var left = 0;
        left &&= missing;
        left ||= 5;
        left ??= missing;
        var holder = {v: null};
        holder.v ??= 6;
        holder.v &&= 7;
        print(left, holder.v);

        var date = new Date(123);
        print(date.getTime());
        var made = new Array(2, 3);
        print(made.length, made[0], made[1]);
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        concat!(
            "1 2 3\n",
            "14\n",
            "10 16 1\n",
            "3 false 16\n",
            "3 8 a,x\n",
            "5 7\n",
            "123\n",
            "2 2 3\n",
        )
    );
}

fn execute(bytes: Vec<u8>) -> String {
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
    String::from_utf8(output.stdout).unwrap()
}

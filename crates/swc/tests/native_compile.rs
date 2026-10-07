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
            "CreateEnvironment",
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
    assert!(recovered.contains(" + _mercury_r2"));
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
fn compiles_function_graphs_and_environment_access() {
    let bytes = compile(
        "function outer(seed) { var value = seed; function add(step) { value += step; return value; } return add; } var closure = outer(1); print(closure(2));",
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let names = raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .map(|instruction| instruction.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(raw.functions.len(), 3);
    assert!(names.contains(&"CreateClosure"));
    assert!(names.contains(&"LoadParam"));
    assert!(names.contains(&"GetEnvironment"));
    assert!(names.contains(&"LoadFromEnvironment"));
    assert!(names.contains(&"StoreToEnvironment"));
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn compiles_arrow_bodies_and_call_only_headers() {
    let bytes = compile(
        "var add = (left, right) => left + right; var twice = value => { let result = value * 2; return result; }; print(add(2, twice(3)));",
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let names = raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .map(|instruction| instruction.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(raw.functions.len(), 3);
    assert_eq!(raw.functions[0].flags.prohibit_invoke, 2);
    assert_eq!(raw.functions[1].flags.prohibit_invoke, 1);
    assert_eq!(raw.functions[2].flags.prohibit_invoke, 1);
    assert!(names.contains(&"LoadParam"));
    assert!(names.contains(&"CreateClosure"));
    assert!(names.contains(&"Ret"));
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn rejects_implicit_arguments_inside_arrows_explicitly() {
    let module = SwcModule::parse(
        "input.js",
        "var first = () => arguments[0];",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let error = HbcCompiler::new(96).compile(&module).unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported: the implicit `arguments` object is not supported by native compilation yet"
    );
}

#[test]
fn compiles_lexical_scopes_and_tdz_checks() {
    let bytes = compile(
        "let outer = 1; { let inner = outer + 1; const fixed = 3; var closure = function () { return inner + fixed; }; } print(closure());",
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let names = raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .map(|instruction| instruction.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(raw.functions[0].environment_size, 1);
    assert!(names.contains(&"ThrowIfHasRestrictedGlobalProperty"));
    assert!(names.contains(&"CreateInnerEnvironment"));
    assert!(names.contains(&"LoadConstEmpty"));
    assert!(names.contains(&"ThrowIfEmpty"));
    assert!(names.contains(&"GetEnvironment"));
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn compiles_constant_writes_as_runtime_type_errors() {
    let bytes = compile(
        "const answer = 42; if (false) answer = 43;",
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

    assert!(names.contains(&"Construct"));
    assert!(names.contains(&"Throw"));
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

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_functions_locals_and_closures_execute() {
    let bytes = compile(
        r#"
        function outer(seed) {
            var value = seed;
            function add(step) { value += step; return value; }
            return add;
        }
        var a = outer(10);
        var b = outer(100);
        print(a(2), a(3), b(1));

        function siblings(start) {
            var value = start;
            function up() { value++; return value; }
            function down() { value--; return value; }
            return [up, down];
        }
        var pair = siblings(5);
        print(pair[0](), pair[1](), pair[0]());

        function levels(a) {
            return function(b) {
                return function(c) { a += b + c; return a; };
            };
        }
        var deepest = levels(1)(2);
        print(deepest(3), deepest(4));

        function hoisted() { return later(); function later() { return 17; } }
        print(hoisted());

        function localFactorial(input) {
            function factorial(value) {
                return value <= 1 ? 1 : value * factorial(value - 1);
            }
            return factorial(input);
        }
        print(localFactorial(5));

        var twice = function(value) { var result = value * 2; return result; };
        print(twice(6));

        function Box(value) { this.value = value; return 1; }
        function Factory() { return {value: 11}; }
        var box = new Box(9);
        var made = new Factory();
        print(box.value, made.value);
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        concat!(
            "12 15 101\n",
            "6 5 6\n",
            "6 12\n",
            "17\n",
            "120\n",
            "12\n",
            "9 11\n",
        )
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_arrows_preserve_bodies_captures_and_lexical_this() {
    let bytes = compile(
        r#"
        var add = (left, right) => left + right;
        var twice = value => { let result = value * 2; return result; };
        var object = value => ({value: value});
        print(add(2, 3), twice(6), object(9).value);

        let outer = 4;
        var capture = value => () => value + outer;
        print(capture(3)());

        var topThis = () => this;
        print(topThis.call({value: 99}) === this, typeof topThis.prototype);

        function Receiver(value) {
            this.value = value;
            this.direct = () => this.value;
            this.nested = () => () => this.value + 1;
            this.ordinary = () => function () { return this.value; };
        }
        var receiver = new Receiver(7);
        print(receiver.direct(), receiver.direct.call({value: 50}));
        print(receiver.nested()(), receiver.ordinary().call({value: 11}));

        function makeRegular() {
            return () => function () { return () => this.value; };
        }
        var regular = makeRegular()();
        var nestedArrow = regular.call({value: 13});
        print(nestedArrow());

        var closures = [];
        for (let index = 0; index < 3; index++) closures[index] = () => index;
        print(closures[0](), closures[1](), closures[2]());
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        concat!(
            "5 12 9\n",
            "7\n",
            "true undefined\n",
            "7 7\n",
            "8 11\n",
            "13\n",
            "0 1 2\n",
        )
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_arrows_cannot_be_constructed() {
    let failure = execute_failure(compile(
        "var arrow = value => value; new arrow(1);",
        SourceLanguage::JavaScript,
    ));
    assert!(failure.contains("TypeError"), "{failure}");
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_lexical_scopes_closures_and_iterations_execute() {
    let bytes = compile(
        r#"
        let top = 4;
        const fixed = 5;
        function topClosure() { return top + fixed; }
        print("top", topClosure(), this.top);

        let shadowed = 1;
        {
            let shadowed = 2;
            shadowed += 3;
            print("inner", shadowed);
        }
        print("outer", shadowed);

        var escaped;
        {
            let captured = 7;
            const offset = 2;
            escaped = function () { captured++; return captured + offset + shadowed; };
        }
        print("escaped", escaped(), escaped());

        let unset;
        let first = 1, second = first + 1;
        print("initialization", unset, first + second);

        var fromWhile = [];
        var index = 0;
        while (index < 3) {
            let current = index;
            fromWhile[index] = function () { return current; };
            index++;
        }
        print(fromWhile[0](), fromWhile[1](), fromWhile[2]());

        var fromFor = [];
        for (let iteration = 0; iteration < 3; iteration++) {
            fromFor[iteration] = function () { return iteration; };
        }
        print(fromFor[0](), fromFor[1](), fromFor[2]());
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        concat!(
            "top 9 undefined\n",
            "inner 5\n",
            "outer 1\n",
            "escaped 11 12\n",
            "initialization undefined 3\n",
            "0 1 2\n",
            "0 1 2\n",
        )
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_lexical_tdz_reads_and_writes_fail() {
    for source in [
        "function fail() { print(value); let value = 1; } fail();",
        "function fail() { value = 1; let value; } fail();",
        "function fail() { return typeof value; let value = 1; } fail();",
        "function fail() { value = 1; const value = 2; } fail();",
    ] {
        let failure = execute_failure(compile(source, SourceLanguage::JavaScript));
        assert!(failure.contains("ReferenceError"), "{failure}");
    }

    for source in [
        "const value = 1; value = 2;",
        "function fail() { const value = 1; value++; } fail();",
        "function outer() { const value = 1; return function () { value += 2; }; } outer()();",
    ] {
        let failure = execute_failure(compile(source, SourceLanguage::JavaScript));
        assert!(failure.contains("TypeError"), "{failure}");
    }

    let failure = execute_failure(compile("let undefined = 1;", SourceLanguage::JavaScript));
    assert!(failure.contains("SyntaxError"), "{failure}");
}

fn execute(bytes: Vec<u8>) -> String {
    let output = execute_output(bytes);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn execute_failure(bytes: Vec<u8>) -> String {
    let output = execute_output(bytes);
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn execute_output(bytes: Vec<u8>) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "mercury-native-compile-{}-{}.hbc",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, bytes).unwrap();
    let hermes = std::env::var_os("HERMES_BIN").expect("HERMES_BIN must point to Hermes 0.12");
    let output = Command::new(hermes).arg(&path).output().unwrap();
    let _ = fs::remove_file(path);
    output
}

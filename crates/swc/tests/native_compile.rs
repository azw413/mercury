use std::{fs, process::Command};

use mercury_binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_ir::RawOperand;
use mercury_spec_builtin::load_spec;
use mercury_swc::{
    HbcCompiler, SourceKind, SourceLanguage, SwcModule,
    ast::Ident,
    decompile,
    visit::{VisitMut, VisitMutWith},
};

fn compile(source: &str, language: SourceLanguage) -> Vec<u8> {
    let module = SwcModule::parse("input", source, language, SourceKind::Script).unwrap();
    HbcCompiler::new(96).compile(&module).unwrap()
}

struct RenameGeneratedBindings;

impl VisitMut for RenameGeneratedBindings {
    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        if let Some(suffix) = identifier.sym.as_ref().strip_prefix("_mercury_") {
            identifier.sym = format!("_self_hosted_{suffix}").into();
        }
    }
}

fn rename_generated_bindings(module: &mut SwcModule) {
    module.with_ast(|program| program.visit_mut_with(&mut RenameGeneratedBindings));
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
        "var value = { method() {} };",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let error = HbcCompiler::new(96).compile(&module).unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported: object methods and accessors require native function compilation"
    );
}

#[test]
fn compiles_literal_call_and_constructor_spreads() {
    let bytes = compile(
        "var xs = [1, 2]; var array = [0, ...xs, 3]; var object = {a: 1, ...{b: 2}}; function C(a, b) { this.sum = a + b; } var value = object.sum(0, ...xs); var made = new C(...xs);",
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();
    let builtins = raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.name == "CallBuiltin")
        .filter_map(|instruction| match instruction.operands.get(1) {
            Some(RawOperand::U8(value)) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(builtins.contains(&44), "object spread builtin missing");
    assert!(builtins.contains(&46), "array spread builtin missing");
    assert!(builtins.contains(&47), "spread apply builtin missing");
    decompile(&bytes).unwrap();
}

#[test]
fn compiles_iteration_exponentiation_and_wtf8_strings() {
    let bytes = compile(
        r#"
        var key;
        var target = {};
        for (key in target) target.last = key;
        for (let lexical in target) (() => lexical)();
        for (target.key in target) break;
        for (const item of target) { if (item) break; }
        var value = 2 ** 3;
        value **= 2;
        target.value **= value;
        var lone = "\ud800";
        "#,
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

    assert!(names.contains(&"GetPNameList"));
    assert!(names.contains(&"GetNextPName"));
    assert!(names.contains(&"IteratorBegin"));
    assert!(names.contains(&"IteratorNext"));
    assert!(names.contains(&"IteratorClose"));
    assert!(names.contains(&"CallBuiltin"));
    assert!(raw
        .functions
        .iter()
        .any(|function| !function.exception_handlers.is_empty()));
    assert!(container
        .small_string_table_entries
        .iter()
        .any(|entry| entry.is_utf16 && entry.length == 1));
    decompile(&bytes).unwrap();
}

#[test]
fn compiles_switch_fallthrough_breaks_and_outer_continues() {
    let bytes = compile(
        "function choose(value) { var result = 0; switch (value) { case 1: result += 1; case 2: result += 2; break; default: result = 9; } return result; } var count = 0; while (count < 2) { count++; switch (count) { case 1: continue; default: break; } } print(choose(1), choose(2), choose(3));",
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

    assert!(names.contains(&"StrictEq"));
    assert!(names.contains(&"JmpTrueLong"));
    assert!(decompile(&bytes).is_ok());
}

#[test]
fn compiles_self_hosted_runtime_boundary_opcodes() {
    let bytes = compile(
        r#"
        function invoke(callback) {
            try { return callback(1, 2, 3, 4); }
            finally { print("finally"); }
        }
        function Constructor() {
            print(new.target === Constructor);
            this.value = 1;
            print(delete this.value);
        }
        function add(a, b, c, d) { return a + b + c + d; }
        print(invoke(add));
        new Constructor();
        "#,
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

    for expected in ["Call", "GetNewTarget", "DelById", "Catch", "Throw"] {
        assert!(names.contains(&expected), "missing {expected}");
    }
    assert!(
        raw.functions
            .iter()
            .map(|function| function.exception_handlers.len())
            .sum::<usize>()
            >= 1
    );
}

#[test]
fn compiles_strict_functions_and_general_exception_regions() {
    let bytes = compile(
        r#"
        "use strict";
        function flow(value) {
            try {
                if (value) throw value;
                return this;
            } catch (error) {
                return error;
            } finally {
                print("cleanup");
            }
        }
        flow();
        "#,
        SourceLanguage::JavaScript,
    );
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, &bytes, &spec.bytecode).unwrap();

    assert!(raw.functions[0].flags.strict_mode);
    assert!(raw.functions.iter().all(|function| function.flags.strict_mode));
    assert!(raw
        .functions
        .iter()
        .any(|function| !function.exception_handlers.is_empty()));
    assert!(raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .any(|instruction| instruction.name == "Catch"));
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
fn compiles_rich_parameters_bindings_and_arguments() {
    let bytes = compile(
        r#"
        function sample(first = 1, [second, ...tail], {value: renamed, extra = 3, ...rest}) {
            let [local = 4] = tail;
            const {kept, ...others} = rest;
            return () => [arguments.length, first, second, renamed, extra, local, kept, others];
        }
        var collect = (first = 1, ...rest) => [first, rest];
        "#,
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

    assert!(names.contains(&"ReifyArguments"));
    assert!(names.contains(&"CallBuiltin"));
    assert!(names.contains(&"JmpUndefinedLong"));
    assert!(names.contains(&"GetByVal"));
    assert!(names.contains(&"PutOwnByVal"));
    assert!(names.contains(&"CreateClosure"));
    decompile(&bytes).unwrap();
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
fn native_spreads_execute_and_self_host() {
    let source = include_str!("fixtures/spread.js");
    let expected = concat!(
        "array 8 false 0||1|2|3|a|b|\n",
        "object 1 6 5\n",
        "call 16\n",
        "new 6 true\n",
        "events array0,array1,array2,get,callee,call0,call1,new0,new1\n",
    );
    let original = compile(source, SourceLanguage::JavaScript);
    assert_eq!(execute(original.clone()), expected);
    let recovered = decompile(&original).unwrap();
    let rebuilt = HbcCompiler::new(96).compile(&recovered).unwrap();
    assert_eq!(execute(rebuilt), expected);
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
fn native_self_hosted_control_flow_roundtrip_survives_renaming() {
    let original = include_bytes!("fixtures/control_flow.hbc");
    let mut module = decompile(original).unwrap();
    rename_generated_bindings(&mut module);
    assert!(module.print().contains("_self_hosted_pc"));

    let rebuilt = HbcCompiler::new(96).compile(&module).unwrap();
    assert_eq!(execute(original.to_vec()), "18\n");
    assert_eq!(execute(rebuilt), "18\n");
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_self_hosted_large_fixtures_roundtrip_survives_renaming() {
    let expected_box2d = (0..20)
        .map(|step| format!("Completed step {step}\n"))
        .collect::<String>();
    for (original, expected) in [
        (&include_bytes!("../../../test/hex.hbc")[..], "".to_owned()),
        (
            &include_bytes!("../../../test/box2d.hbc")[..],
            expected_box2d,
        ),
    ] {
        let mut module = decompile(original).unwrap();
        rename_generated_bindings(&mut module);
        let rebuilt = HbcCompiler::new(96).compile(&module).unwrap();

        assert_eq!(execute(original.to_vec()), expected);
        assert_eq!(execute(rebuilt), expected);
    }
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_self_hosted_runtime_boundaries_execute() {
    let bytes = compile(
        r#"
        function invoke(callback) {
            try { return callback(1, 2, 3, 4); }
            finally { print("finally"); }
        }
        function Constructor() {
            print(new.target === Constructor);
            this.value = 1;
            print(delete this.value, this.value);
        }
        function add(a, b, c, d) { return a + b + c + d; }
        print(invoke(add));
        new Constructor();
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(execute(bytes), "finally\n10\ntrue\ntrue undefined\n");

    let failure = execute_output(compile(
        "function fail() { try { return missing(); } finally { print('cleanup'); } } fail();",
        SourceLanguage::JavaScript,
    ));
    assert!(!failure.status.success());
    assert_eq!(String::from_utf8(failure.stdout).unwrap(), "cleanup\n");
    assert!(String::from_utf8_lossy(&failure.stderr).contains("ReferenceError"));
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_strictness_and_general_exception_control_flow_execute() {
    let bytes = compile(
        r#"
        "use strict";
        function strictReceiver() { return this === undefined; }

        var log = "";
        function flow(mode) {
            try {
                if (mode === 0) return "returned";
                if (mode === 1) throw "thrown";
                return "normal";
            } catch (error) {
                return "caught:" + error;
            } finally {
                log += "f" + mode;
            }
        }

        function loop() {
            for (var index = 0; index < 3; index++) {
                try {
                    if (index === 0) continue;
                    if (index === 1) break;
                } finally {
                    log += "l" + index;
                }
            }
        }

        function overriddenReturn() {
            try { return 1; } finally { return 2; }
        }
        function overriddenThrow() {
            try { throw 1; }
            catch (error) { throw 2; }
            finally { throw 3; }
        }
        function cleanupThrowsOnce() {
            try { return 1; }
            finally { log += "x"; throw 7; }
        }

        print(strictReceiver());
        print(flow(0), flow(1), flow(2));
        loop();
        print(log, overriddenReturn());
        try { overriddenThrow(); } catch (error) { print(error); }
        try { cleanupThrowsOnce(); } catch (error) { print(error, log); }
        "#,
        SourceLanguage::JavaScript,
    );
    assert_eq!(
        execute(bytes),
        concat!(
            "true\n",
            "returned caught:thrown normal\n",
            "f0f1f2l0l1 2\n",
            "3\n",
            "7 f0f1f2l0l1x\n",
        )
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_for_in_exponentiation_and_wtf8_strings_execute() {
    let bytes = compile(
        r#"
        var parent = { inherited: 1 };
        var object = Object.create(parent);
        object.first = 1;
        object.second = 2;
        var names = [];
        for (var key in object) {
            if (key === "second") continue;
            names.push(key);
            if (key === "inherited") break;
        }

        var closures = [];
        for (let name in { alpha: 1, beta: 2 }) closures.push(() => name);
        var constants = [];
        for (const name in { gamma: 3, delta: 4 }) constants.push(() => name);
        var target = {};
        for (target.key in { assigned: true }) {}

        var order = "";
        function base() { order += "b"; return 2; }
        function power() { order += "p"; return 3; }
        var holder = { value: 2 };
        holder.value **= 3;
        var lone = "\ud800";

        print(names.join(","));
        print(closures[0](), closures[1](), constants[0](), constants[1](), target.key);
        print(base() ** power(), order, holder.value);
        print(lone.length, lone.charCodeAt(0));
        "#,
        SourceLanguage::JavaScript,
    );
    let expected = concat!(
        "first,inherited\n",
        "alpha beta gamma delta assigned\n",
        "8 bp 8\n",
        "1 55296\n",
    );
    let recovered = decompile(&bytes).unwrap();
    assert_eq!(execute(bytes), expected);
    let rebuilt = HbcCompiler::new(96).compile(&recovered).unwrap();
    assert_eq!(execute(rebuilt), expected);
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_for_of_closes_iterators_and_preserves_lexical_bindings() {
    let source = format!(
        "{}\n{}",
        include_str!("fixtures/iteration.js"),
        r#"
        var returnLog = [];
        var returning = {};
        returning[Symbol.iterator] = function () {
            var finished = false;
            return {
                next: function () {
                    if (finished) return { done: true };
                    finished = true;
                    return { value: 7, done: false };
                },
                return: function () {
                    returnLog.push("return");
                    return {};
                }
            };
        };
        function returnFromLoop() {
            for (const item of returning) {
                try { return item; }
                finally { returnLog.push("finally"); }
            }
        }
        var captures = [];
        for (let item of [5, 6]) captures.push(() => item);
        var bindingLog = [];
        var bindingSource = {};
        bindingSource[Symbol.iterator] = function () {
            return {
                next: function () { return { value: null, done: false }; },
                return: function () { bindingLog.push("return"); return {}; }
            };
        };
        try { for (const { value } of bindingSource) {} }
        catch (error) { print("binding-close", error instanceof TypeError, bindingLog.join(",")); }
        var nextLog = [];
        var throwingNext = {};
        throwingNext[Symbol.iterator] = function () {
            return {
                next: function () { throw "next"; },
                return: function () { nextLog.push("return"); return {}; }
            };
        };
        try { for (var ignored of throwingNext) {} }
        catch (error) { print("next-failure", error, nextLog.length); }
        print("return-close", returnFromLoop(), returnLog.join(","));
        print("for-of-bindings", captures[0](), captures[1]());
        "#,
    );
    let expected = concat!(
        "for-in first,shadowed,inherited\n",
        "for-in-values 0,1 0\n",
        "array-iterator 1,undefined,3,4\n",
        "iterator-close next,value:1,return\n",
        "invalid-next true\n",
        "break-close close\n",
        "throw-close body\n",
        "binding-close true return\n",
        "next-failure next 0\n",
        "return-close 7 finally,return\n",
        "for-of-bindings 5 6\n",
    );
    let bytes = compile(&source, SourceLanguage::JavaScript);
    let recovered = decompile(&bytes).unwrap();
    assert_eq!(execute(bytes), expected);
    let rebuilt = HbcCompiler::new(96).compile(&recovered).unwrap();
    assert_eq!(execute(rebuilt), expected);
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_rich_parameters_bindings_and_arguments_execute() {
    let bytes = compile(
        r#"
        var defaultsRun = 0;
        function defaults(first = (defaultsRun++, 2), second = first + 3) {
            return [first, second, defaultsRun];
        }
        var d1 = defaults(undefined);
        var d2 = defaults(7, undefined);
        print(d1[0], d1[1], d1[2]);
        print(d2[0], d2[1], d2[2]);

        function collect(head, ...tail) { return [head, tail.length, tail[0], tail[1]]; }
        var collected = collect(1, 2, 3);
        print(collected[0], collected[1], collected[2]);
        print(collected[3]);

        var arrowRest = (first = 2, ...tail) => [first, tail.length, tail[0]];
        var arrowCollected = arrowRest(undefined, 9);
        print(arrowCollected[0], arrowCollected[1], arrowCollected[2]);

        function argumentDefault(first = arguments[1], second) { return first; }
        print(argumentDefault(undefined, 6));

        var outerDefault = 7;
        function scopedDefault(first = outerDefault) { var outerDefault = 1; return [first, outerDefault]; }
        var scoped = scopedDefault();
        print(scoped[0], scoped[1]);
        function copiedParameter(first = 3) { var first; return first; }
        function varArguments(first = 1) { var arguments; return arguments.length; }
        print(copiedParameter(), varArguments());

        function characters([first, , third, ...tail]) { return [first, third, tail.length, tail[0]]; }
        var chars = characters("abcd");
        print(chars[0], chars[1], chars[2]);
        print(chars[3]);

        function patterns([first, , third = 9, ...tail], {x: renamed, y = 5, ...rest}) {
            let [local = 7] = tail;
            const {z, ...others} = rest;
            return [first, third, local, renamed, y, z, others.w];
        }
        var patterned = patterns([1, 2, undefined, 8], {x: 3, z: 4, w: 6});
        print(patterned[0], patterned[1], patterned[2]);
        print(patterned[3], patterned[4], patterned[5]);
        print(patterned[6]);

        function boxed({length, ...rest}) { return [length, rest[0], rest[2]]; }
        var boxedValue = boxed("abc");
        print(boxedValue[0], boxedValue[1], boxedValue[2]);

        var keyCalls = 0;
        function key() { keyCalls++; return "x"; }
        function computed({[key()]: found, ...rest}) { return [found, rest.y, keyCalls]; }
        var computedValue = computed({x: 4, y: 8});
        print(computedValue[0], computedValue[1], computedValue[2]);

        function inspect(a, b) {
            var captured = () => arguments;
            a = 9;
            arguments[1] = 8;
            return [arguments.length, arguments[0], b, captured() === arguments];
        }
        var inspected = inspect(1, 2);
        print(inspected[0], inspected[1], inspected[2]);
        print(inspected[3]);

        function shadow(arguments) { return () => arguments; }
        print(shadow(11)());
        "#,
        SourceLanguage::JavaScript,
    );
    let expected = concat!(
        "2 5 1\n", "7 10 1\n", "1 2 2\n", "3\n", "2 1 9\n", "6\n", "7 1\n", "3 0\n", "a c 1\n",
        "d\n", "1 9 8\n", "3 5 4\n", "6\n", "3 a c\n", "4 8 1\n", "2 1 2\n", "true\n", "11\n",
    );
    assert_eq!(execute(bytes.clone()), expected);
    assert_eq!(
        execute_source(&decompile(&bytes).unwrap().print()),
        expected
    );
}

#[test]
#[ignore = "requires HERMES_BIN for an HBC 96 runtime"]
fn native_parameter_tdz_and_null_destructuring_fail() {
    for source in [
        "function fail(first = later, later = 2) {} fail();",
        "function fail({value}) {} fail(null);",
        "function fail([]) {} fail(null);",
    ] {
        let failure = execute_failure(compile(source, SourceLanguage::JavaScript));
        assert!(
            failure.contains("ReferenceError") || failure.contains("TypeError"),
            "{failure}"
        );
    }
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
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn execute_failure(bytes: Vec<u8>) -> String {
    let output = execute_output(bytes);
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn execute_source(source: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "mercury-native-compile-{}-{}.js",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, source).unwrap();
    let hermes = std::env::var_os("HERMES_BIN").expect("HERMES_BIN must point to Hermes 0.12");
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

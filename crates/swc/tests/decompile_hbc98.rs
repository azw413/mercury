use std::{fs, process::Command};

use mercury_hbc::binary::{
    DecodedInstruction, DecodedOperand, MinimalFunction, MinimalModule, build_minimal_module,
};
use mercury_hbc::spec_builtin::load_spec;
use mercury_hbc::{HbcCompiler, SourceKind, SourceLanguage, SwcModule, decompile};

const SOURCE: &str = r#"
print(40 + 2);
var object = {keep: 1, remove: 2};
object.loose = 3;
var key = "remove";
print(delete object[key]);
print(Object.keys(object).join(","));
function strict(value) {
    "use strict";
    var target = {};
    target.strict = value;
    target["comp" + "uted"] = value;
    return arguments[0] + target.strict + target.computed;
}
function outer(x) {
    let captured = x;
    { let nested = 2; captured += nested; }
    return function(y) { return captured + y; };
}
var closure = outer(3);
print(strict(3));
print(closure(4));
print(2 ** 5);
print([0, ...[1, 2]].join(","));
function Point(x, y) { this.x = x; this.y = y; }
var point = new Point(...[4, 5]);
print(point.x + point.y);
switch (point.x) {
    case 4: print("switch"); break;
    default: print("wrong");
}
"#;

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

#[test]
fn native_hbc98_script_decompiles_and_recompiles() {
    let bytecode = compile(SOURCE);
    let recovered = decompile(&bytecode).unwrap();
    let printed = recovered.print();
    assert!(printed.contains("switch"));
    SwcModule::parse(
        "recovered.js",
        &printed,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    let rebuilt = HbcCompiler::new(98).compile(&recovered).unwrap();
    assert_eq!(&rebuilt[8..12], &98_u32.to_le_bytes());
}

fn instruction(name: &str, operands: Vec<DecodedOperand>) -> DecodedInstruction {
    let spec = load_spec(98).unwrap();
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

fn function(name: &str, frame_size: u32, instructions: Vec<DecodedInstruction>) -> MinimalFunction {
    MinimalFunction {
        name: name.into(),
        param_count: 1,
        frame_size,
        environment_size: 0,
        prohibit_invoke: 2,
        strict_mode: false,
        exception_handlers: vec![],
        instructions,
        trailing_tables: vec![],
    }
}

#[test]
fn release_hermesc_bodyless_and_unterminated_functions_decompile() {
    use DecodedOperand::{U8, U16};
    // Release hermesc omits Unreachable: functions proven never called get
    // an empty body, and a function may end after a call that never returns.
    let spec = load_spec(98).unwrap();
    let bytes = build_minimal_module(
        &MinimalModule {
            version: 98,
            global_code_index: 0,
            strings: ["global", "bodyless", "unterminated"]
                .into_iter()
                .map(Into::into)
                .collect(),
            string_kinds: vec![],
            literal_value_buffer: vec![],
            object_key_buffer: vec![],
            object_value_buffer: vec![],
            object_shape_table: vec![],
            reg_exps: vec![],
            num_string_switch_imms: 0,
            functions: vec![
                function(
                    "global",
                    3,
                    vec![
                        instruction("LoadConstUndefined", vec![U8(0)]),
                        instruction("CreateClosure", vec![U8(1), U8(0), U16(1)]),
                        instruction("CreateClosure", vec![U8(2), U8(0), U16(2)]),
                        instruction("Ret", vec![U8(0)]),
                    ],
                ),
                function("bodyless", 0, vec![]),
                function(
                    "unterminated",
                    1,
                    vec![instruction("LoadConstUndefined", vec![U8(0)])],
                ),
            ],
        },
        &spec.bytecode,
    )
    .unwrap();
    let printed = decompile(&bytes).unwrap().print();
    assert!(printed.contains("Unreachable instruction encountered"));
    SwcModule::parse(
        "recovered.js",
        &printed,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
}

#[test]
#[ignore = "requires HERMES98_BIN pointing to an HBC 98 runtime"]
fn native_hbc98_roundtrip_executes_correctly() {
    let bytecode = compile(SOURCE);
    let expected = execute(&bytecode);
    let recovered = decompile(&bytecode).unwrap();
    let rebuilt = HbcCompiler::new(98).compile(&recovered).unwrap();
    assert_eq!(execute(&rebuilt), expected);
}

fn execute(bytes: &[u8]) -> Vec<u8> {
    let path = std::env::temp_dir().join(format!(
        "mercury-decompile-hbc98-{}-{}.hbc",
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
    output.stdout
}

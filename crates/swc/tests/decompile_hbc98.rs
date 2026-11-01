use std::{fs, process::Command};

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

use std::{collections::BTreeMap, fs, process::Command};

use mercury_hbc::binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_hbc::ir::RawOperand;
use mercury_hbc::spec_builtin::load_spec;

fn builtin_index(version: u32, name: &str) -> Option<u32> {
    load_spec(version).unwrap().bytecode.builtin_index(name)
}

fn assert_indices_contiguous(version: u32) {
    let builtins = &load_spec(version).unwrap().bytecode.builtins;
    let indices = builtins
        .iter()
        .map(|builtin| builtin.index)
        .collect::<Vec<_>>();
    assert_eq!(
        indices,
        (0..builtins.len() as u32).collect::<Vec<_>>(),
        "HBC {version} builtin indices are not contiguous"
    );
    let kinds = builtins
        .iter()
        .map(|builtin| serde_json::to_value(&builtin.kind).unwrap())
        .collect::<Vec<_>>();
    assert!(
        !kinds
            .iter()
            .any(|kind| kind.as_str().is_some_and(|k| k.ends_with("_object"))),
        "HBC {version} spec still contains object kinds"
    );
}

#[test]
fn hbc96_builtin_ids_match_hermes() {
    let expected = [
        ("silentSetPrototypeOf", 37),
        ("getTemplateObject", 39),
        ("ensureObject", 40),
        ("getMethod", 41),
        ("throwTypeError", 42),
        ("generatorSetDelegated", 43),
        ("copyDataProperties", 44),
        ("copyRestArgs", 45),
        ("arraySpread", 46),
        ("apply", 47),
        ("exportAll", 48),
        ("exponentiationOperator", 49),
        ("initRegexNamedGroups", 50),
    ];
    for (name, index) in expected {
        assert_eq!(
            builtin_index(96, name),
            Some(index),
            "HBC 96 builtin {name}"
        );
    }
    assert_indices_contiguous(96);
}

#[test]
fn hbc98_builtin_ids_match_hermes() {
    let expected = [
        ("silentSetPrototypeOf", 39),
        ("getTemplateObject", 41),
        ("ensureObject", 42),
        ("getMethod", 43),
        ("throwTypeError", 44),
        ("throwReferenceError", 45),
        ("copyDataProperties", 46),
        ("copyRestArgs", 47),
        ("arraySpread", 48),
        ("apply", 49),
        ("applyArguments", 50),
        ("applyWithNewTarget", 51),
        ("exponentiationOperator", 53),
        ("initRegexNamedGroups", 54),
    ];
    for (name, index) in expected {
        assert_eq!(
            builtin_index(98, name),
            Some(index),
            "HBC 98 builtin {name}"
        );
    }
    assert_eq!(
        builtin_index(98, "generatorSetDelegated"),
        None,
        "HBC 98 has no generatorSetDelegated builtin"
    );
    assert_indices_contiguous(98);
}

#[test]
fn legacy_specs_have_contiguous_builtin_ids() {
    for version in [89, 94] {
        assert_indices_contiguous(version);
        assert_eq!(builtin_index(version, "copyRestArgs"), Some(45));
    }
}

/// Runs `hermesc` on `source`, returning `(binary bytes, disassembly text)`.
fn hermesc_compile(hermesc: &std::ffi::OsStr, source: &str, extra: &[&str]) -> (Vec<u8>, String) {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("input.js");
    let binary_path = directory.path().join("input.hbc");
    fs::write(&source_path, source).unwrap();

    let compile = Command::new(hermesc)
        .args(extra)
        .args(["-emit-binary", "-out"])
        .arg(&binary_path)
        .arg(&source_path)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "hermesc failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let dump = Command::new(hermesc)
        .args(extra)
        .arg("-dump-bytecode")
        .arg(&source_path)
        .output()
        .unwrap();
    assert!(
        dump.status.success(),
        "hermesc -dump-bytecode failed: {}",
        String::from_utf8_lossy(&dump.stderr)
    );

    (
        fs::read(&binary_path).unwrap(),
        String::from_utf8(dump.stdout).unwrap(),
    )
}

/// Every builtin name on a `CallBuiltin`/`CallBuiltinLong` disassembly line:
/// the quoted operand, with the `HermesBuiltin.` prefix stripped when present
/// (static builtins print as `"Object.method"`).
fn dump_builtin_names(dump: &str) -> Vec<String> {
    dump.lines()
        .filter(|line| line.contains("CallBuiltin"))
        .filter_map(|line| {
            let start = line.find('"')? + 1;
            let end = line[start..].find('"')? + start;
            let name = &line[start..end];
            Some(
                name.strip_prefix("HermesBuiltin.")
                    .unwrap_or(name)
                    .to_owned(),
            )
        })
        .collect()
}

/// Every builtin operand on `CallBuiltin`/`CallBuiltinLong` instructions in
/// the binary, decoded with the spec matching its header version.
fn binary_builtin_ids(bytes: &[u8]) -> Vec<u32> {
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let spec = load_spec(version).unwrap();
    let container = parse_hbc_container_with_spec(bytes, &spec.container).unwrap();
    let raw = decode_raw_module(&container, bytes, &spec.bytecode).unwrap();
    raw.functions
        .iter()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| {
            matches!(instruction.name.as_str(), "CallBuiltin" | "CallBuiltinLong")
        })
        .map(|instruction| match instruction.operands[1] {
            RawOperand::U8(value) => u32::from(value),
            RawOperand::U32(value) => value,
            ref other => panic!("unexpected builtin operand {other:?}"),
        })
        .collect()
}

fn assert_dump_and_binary_builtin_ids_agree(bytes: &[u8], dump: &str) {
    let names = dump_builtin_names(dump);
    let ids = binary_builtin_ids(bytes);
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let spec = load_spec(version).unwrap();
    let from_names = names
        .iter()
        .map(|name| {
            spec.bytecode
                .builtin_index(name)
                .unwrap_or_else(|| panic!("dumped builtin {name} missing from HBC {version} spec"))
        })
        .collect::<Vec<_>>();
    let histogram = |values: &[u32]| {
        values.iter().fold(BTreeMap::new(), |mut map, value| {
            *map.entry(*value).or_insert(0usize) += 1;
            map
        })
    };
    assert_eq!(
        histogram(&from_names),
        histogram(&ids),
        "dumped {names:?} vs binary {ids:?}"
    );
}

const PRIVATE_BUILTINS_PROGRAM: &str = r#"
function tagged(strings, value) { return strings[0] + value; }
function collect(first, ...rest) { return rest.length + first; }
function sink() { return arguments.length; }
function Box(v) { this.value = v; }
function* delegate() { yield* spread; }
var box = { __proto__: {kind: "proto"} };
var clone = { a: 1, ...box };
var spread = [0, ...[1, 2]];
print(tagged`v${3}`, collect(1, 2, 3), sink(...spread));
print(new Box(...[9]).value, 2 ** 5, /(?<word>\w+)/.exec("abc").groups.word);
try { var [x] = null; } catch (e) { print(e instanceof TypeError); }
try { print(y); let y = 1; } catch (e) { print(e instanceof ReferenceError); }
"#;

const STATIC_BUILTINS_PROGRAM: &str = r#"
print(Math.max(1, 5), Array.isArray([1]), Object.keys({a: 1}).length);
"#;

#[test]
#[ignore = "requires HERMESC_BIN for a Hermes compiler"]
fn hermesc_builtin_ids_match_the_dump() {
    let hermesc =
        std::env::var_os("HERMESC_BIN").expect("HERMESC_BIN must point to a Hermes compiler");
    let (bytes, dump) = hermesc_compile(&hermesc, PRIVATE_BUILTINS_PROGRAM, &[]);
    assert_dump_and_binary_builtin_ids_agree(&bytes, &dump);
    let (bytes, dump) = hermesc_compile(&hermesc, STATIC_BUILTINS_PROGRAM, &["-fstatic-builtins"]);
    assert_dump_and_binary_builtin_ids_agree(&bytes, &dump);
}

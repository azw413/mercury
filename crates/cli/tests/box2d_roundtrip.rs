use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "mercury-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test")
        .join(name)
}
fn run(program: &Path, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("{}: {err}", program.display()))
}
fn mercury(args: &[&str]) -> Output {
    run(Path::new(env!("CARGO_BIN_EXE_mercury-cli")), args)
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn decode(input: &Path) -> String {
    success(mercury(&[
        "decode",
        input.to_str().unwrap(),
        "--format",
        "semantic",
    ]))
}
fn assemble(scratch: &Scratch, name: &str, text: &str) -> PathBuf {
    let source = scratch.path(&format!("{name}.txt"));
    let binary = scratch.path(&format!("{name}.hbc"));
    fs::write(&source, text).unwrap();
    success(mercury(&[
        "assemble",
        source.to_str().unwrap(),
        "-o",
        binary.to_str().unwrap(),
    ]));
    binary
}
fn edited(text: &str) -> String {
    assert_eq!(text.matches("load_immediate r1, 20\n").count(), 1);
    text.replace("\"Completed step \"", "\"Edited step \"")
        .replace("load_immediate r1, 20\n", "load_immediate r1, 3\n")
}
fn canonical(text: &str) -> String {
    text.lines()
        .filter(|line| !line.starts_with("input "))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn box2d_editing_loop_is_self_contained_and_deterministic() {
    let scratch = Scratch::new();
    let original = decode(&fixture("box2d.hbc"));
    assert!(
        !original.contains("0000:"),
        "semantic offsets must be display-only"
    );
    let rebuilt = assemble(&scratch, "rebuilt", &original);
    let rebuilt_text = decode(&rebuilt);
    assert_eq!(canonical(&rebuilt_text), canonical(&original));
    let edited_text = edited(&original);
    let edited_binary = assemble(&scratch, "edited", &edited_text);
    assert_eq!(canonical(&decode(&edited_binary)), canonical(&edited_text));
    let repeat = assemble(&scratch, "repeat", &edited_text);
    assert_eq!(fs::read(edited_binary).unwrap(), fs::read(repeat).unwrap());
}

#[test]
#[ignore = "requires HERMES_BIN pointing to a version-96 Hermes executable"]
fn box2d_rebuild_and_deliberate_edit_execute_in_hermes() {
    let hermes = PathBuf::from(
        std::env::var_os("HERMES_BIN").expect("set HERMES_BIN to a version-96 Hermes executable"),
    );
    let version = success(run(&hermes, &["-version"]));
    assert!(
        version.contains("HBC bytecode version: 96"),
        "incompatible runtime: {version}"
    );
    let scratch = Scratch::new();
    let input = fixture("box2d.hbc");
    let original_stdout = success(run(&hermes, &["-b", input.to_str().unwrap()]));
    assert_eq!(
        original_stdout,
        (0..20)
            .map(|i| format!("Completed step {i}\n"))
            .collect::<String>()
    );
    let text = decode(&input);
    let rebuilt = assemble(&scratch, "rebuilt", &text);
    assert_eq!(
        success(run(&hermes, &["-b", rebuilt.to_str().unwrap()])),
        original_stdout
    );
    let edited_binary = assemble(&scratch, "edited", &edited(&text));
    assert_eq!(
        success(run(&hermes, &["-b", edited_binary.to_str().unwrap()])),
        "Edited step 0\nEdited step 1\nEdited step 2\n"
    );
}

#[test]
fn invalid_assembly_never_overwrites_output() {
    let scratch = Scratch::new();
    let source = scratch.path("invalid.txt");
    let output = scratch.path("existing.hbc");
    fs::write(&output, b"keep this file").unwrap();
    for (body, expected) in [
        ("return r256", "out of range"),
        ("return r0, r1", "operand count"),
        ("return r2", "outside frame"),
        ("unknown_op r0", "unsupported mnemonic"),
        ("load_const_string r0, 0", "missing string"),
        ("create_closure r0, r0, 4", "missing function"),
    ] {
        fs::write(
            &source,
            format!("bytecode_version 96\n.function @f params=1 frame=1 env=0\n{body}\n.end\n"),
        )
        .unwrap();
        let result = mercury(&[
            "assemble",
            source.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ]);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&output).unwrap(), b"keep this file");
    }
}

#[test]
fn decode_marks_unsupported_runtime_metadata_for_assembly_rejection() {
    let scratch = Scratch::new();
    let mut bytes = fs::read(fixture("box2d.hbc")).unwrap();
    bytes[128 + 15] |= 4; // strictMode in the first small function header.
    let input = scratch.path("strict.hbc");
    fs::write(&input, bytes).unwrap();
    let text = decode(&input);
    assert!(text.contains(".unsupported runtime flags or exception handlers in function @f0"));
    let source = scratch.path("strict.txt");
    let output = scratch.path("strict-rebuilt.hbc");
    fs::write(&source, text).unwrap();
    let result = mercury(&[
        "assemble",
        source.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("semantic rebuild does not support"));
    assert!(!output.exists());
}

#[test]
fn unicode_strings_names_and_negative_zero_survive_text_roundtrip() {
    let scratch = Scratch::new();
    let source = "bytecode_version 96\n.function @f name=\"a name \\u0000 ☃\" params=1 frame=1 env=0\nload_const_string r0, \"\\u0000\\b☃\"\nload_immediate r0, -0.0\nreturn r0\n.end\n";
    let binary = assemble(&scratch, "unicode", source);
    let text = decode(&binary);
    assert!(text.contains("load_immediate r0, -0.0"));
    let rebuilt = assemble(&scratch, "unicode-rebuilt", &text);
    assert_eq!(fs::read(binary).unwrap(), fs::read(rebuilt).unwrap());
}

#[test]
fn edited_property_keys_are_promoted_to_identifiers() {
    let scratch = Scratch::new();
    let source = "bytecode_version 96\n.strings\ns0 = \"key\"\n.end\n.function @f params=1 frame=2 env=0\nget_global_object r0\nget_by_id r1, r0, 0, \"key\"\nreturn r1\n.end\n";
    let binary = assemble(&scratch, "identifier", source);
    assert!(decode(&binary).contains("i0 = \"key\""));
}

#[test]
fn version_mismatches_are_explicit_errors() {
    let scratch = Scratch::new();
    let source = scratch.path("version.txt");
    fs::write(
        &source,
        "bytecode_version 94\n.function @f params=1 frame=1 env=0\nreturn r0\n.end\n",
    )
    .unwrap();
    let output = scratch.path("version.hbc");
    for extra in [vec![], vec!["--target-version", "96"]] {
        let mut args = vec![
            "assemble",
            source.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ];
        args.extend(extra);
        let result = mercury(&args);
        assert!(!result.status.success());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("only bytecode version 96") || stderr.contains("cross-version"),
            "{stderr}"
        );
        assert!(!output.exists());
    }
}

#[test]
fn new_literal_edits_extend_the_string_table() {
    let scratch = Scratch::new();
    let source = "bytecode_version 96\n.function @f params=1 frame=1 env=0\nload_const_string r0, \"old\"\nreturn r0\n.end\n";
    let original = assemble(&scratch, "old", source);
    let edited = decode(&original).replace(
        "load_const_string r0, \"old\"",
        "load_const_string r0, \"new\"",
    );
    let rebuilt = assemble(&scratch, "new", &edited);
    let text = decode(&rebuilt);
    assert!(text.contains("load_const_string r0, \"new\""));
    assert!(
        text.contains("s0 = \"old\""),
        "existing buffer string ids must stay stable"
    );
}

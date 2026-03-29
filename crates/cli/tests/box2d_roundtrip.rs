use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn hermes_binary() -> PathBuf {
    workspace_root()
        .parent()
        .expect("workspace parent")
        .join("hermes")
}

fn unique_temp_path(name: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("mercury-{name}-{nanos}.{extension}"))
}

fn run_command(program: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", program.display()));
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
#[ignore = "semantic assembly does not yet fully serialize hbc96 literal/object buffer and shape-table data needed by box2d"]
fn roundtrips_box2d_through_semantic_cli_and_preserves_stdout() {
    let workspace = workspace_root();
    let input_hbc = workspace.join("test/box2d.hbc");
    let hermes = hermes_binary();
    let mercury = PathBuf::from(env!("CARGO_BIN_EXE_mercury-cli"));
    let semantic_path = unique_temp_path("box2d-semantic", "txt");
    let rebuilt_hbc = unique_temp_path("box2d-rebuilt", "hbc");

    assert!(input_hbc.exists(), "missing fixture {}", input_hbc.display());
    assert!(hermes.exists(), "missing hermes binary {}", hermes.display());

    let (orig_code, orig_stdout, orig_stderr) =
        run_command(&hermes, &["-b", input_hbc.to_str().expect("utf-8 path")]);
    assert_eq!(orig_code, 0, "original run failed: {orig_stderr}");

    let (decode_code, _decode_stdout, decode_stderr) = run_command(
        &mercury,
        &[
            "decode",
            input_hbc.to_str().expect("utf-8 path"),
            "--format",
            "semantic",
            "-o",
            semantic_path.to_str().expect("utf-8 path"),
        ],
    );
    assert_eq!(decode_code, 0, "decode failed: {decode_stderr}");
    assert!(semantic_path.exists(), "decode did not write semantic output");

    let (assemble_code, _assemble_stdout, assemble_stderr) = run_command(
        &mercury,
        &[
            "assemble",
            semantic_path.to_str().expect("utf-8 path"),
            "--target-version",
            "96",
            "-o",
            rebuilt_hbc.to_str().expect("utf-8 path"),
        ],
    );
    assert_eq!(assemble_code, 0, "assemble failed: {assemble_stderr}");
    assert!(rebuilt_hbc.exists(), "assemble did not write rebuilt hbc");

    let (rebuilt_code, rebuilt_stdout, rebuilt_stderr) =
        run_command(&hermes, &["-b", rebuilt_hbc.to_str().expect("utf-8 path")]);
    assert_eq!(rebuilt_code, 0, "rebuilt run failed: {rebuilt_stderr}");
    assert_eq!(rebuilt_stdout, orig_stdout, "rebuilt runtime stdout changed");

    let _ = fs::remove_file(semantic_path);
    let _ = fs::remove_file(rebuilt_hbc);
}

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use mercury_hbc::{HbcCompiler, decompile};

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES_BIN for HBC 96"]
fn hermesc_javascript_corpus_roundtrips_with_identical_execution() {
    run_corpus(96, "HERMES_BIN");
}

#[test]
#[ignore = "requires HERMESC_BIN and HERMES98_BIN for HBC 98"]
fn hermesc_hbc98_javascript_corpus_roundtrips_with_identical_execution() {
    run_corpus(98, "HERMES98_BIN");
}

fn run_corpus(version: u32, runtime_variable: &str) {
    let hermesc = required_tool("HERMESC_BIN", version);
    let hermes = required_tool(runtime_variable, version);
    let files = corpus_files();
    assert!(!files.is_empty(), "the JavaScript corpus is empty");
    let modes = hermesc_modes();

    let mut failures = Vec::new();
    for path in &files {
        for mode in &modes {
            if let Err(error) = roundtrip_fixture(path, mode, &hermes, &hermesc, version) {
                failures.push(format!("{} ({mode}):\n{error}", path.display()));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus cases failed:\n\n{}",
        failures.len(),
        files.len() * modes.len(),
        failures.join("\n\n")
    );
}

fn required_tool(name: &str, version: u32) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("set {name} to a version-{version} Hermes executable"))
}

fn corpus_files() -> Vec<PathBuf> {
    let roots = match env::var_os("MERCURY_JS_CORPUS") {
        Some(paths) => env::split_paths(&paths).collect::<Vec<_>>(),
        None => {
            let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
            vec![tests.join("fixtures"), tests.join("corpus")]
        }
    };
    let filter = env::var("MERCURY_JS_CORPUS_FILTER").ok();
    let limit = env::var("MERCURY_JS_CORPUS_LIMIT").ok().map(|value| {
        let limit = value
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("MERCURY_JS_CORPUS_LIMIT must be a positive integer"));
        assert!(limit > 0, "MERCURY_JS_CORPUS_LIMIT must be positive");
        limit
    });

    let mut files = Vec::new();
    for root in roots {
        collect_javascript(&root, &mut files);
    }
    files.sort();
    if let Some(filter) = filter {
        files.retain(|path| path.to_string_lossy().contains(&filter));
    }
    if let Some(limit) = limit {
        files.truncate(limit);
    }
    files
}

fn hermesc_modes() -> Vec<String> {
    match env::var("MERCURY_HERMESC_MODES") {
        Ok(value) => {
            let modes = value
                .split(',')
                .map(str::trim)
                .filter(|mode| !mode.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(!modes.is_empty(), "MERCURY_HERMESC_MODES is empty");
            modes
        }
        Err(_) => vec!["-O0".into(), "-O".into()],
    }
}

fn collect_javascript(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "js") {
            files.push(path.to_owned());
        }
        return;
    }
    let mut children = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("cannot read corpus path {}: {error}", path.display()))
        .map(|entry| entry.expect("cannot read corpus directory entry").path())
        .collect::<Vec<_>>();
    children.sort();
    for child in children {
        collect_javascript(&child, files);
    }
}

fn roundtrip_fixture(
    path: &Path,
    optimization: &str,
    hermes: &Path,
    hermesc: &Path,
    version: u32,
) -> Result<(), String> {
    let directory = tempfile::tempdir().map_err(|error| format!("temporary directory: {error}"))?;
    let original_path = directory.path().join("original.hbc");
    let rebuilt_path = directory.path().join("rebuilt.hbc");

    let mut compiler = Command::new(hermesc);
    if version == 96 {
        compiler.arg("-Xes6-class");
    }
    let compilation = compiler
        .args([optimization, "-g0", "-emit-binary"])
        .arg(format!("-out={}", original_path.display()))
        .arg(path)
        .output()
        .map_err(|error| format!("launching hermesc: {error}"))?;
    if !compilation.status.success() {
        return Err(format!(
            "hermesc failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            compilation.status.code(),
            String::from_utf8_lossy(&compilation.stdout),
            String::from_utf8_lossy(&compilation.stderr),
        ));
    }

    let original_bytes =
        fs::read(&original_path).map_err(|error| format!("reading reference bytecode: {error}"))?;
    let reference = execute(hermes, &original_path, directory.path(), version)?;
    let recovered = decompile(&original_bytes).map_err(|error| format!("decompile: {error}"))?;
    let rebuilt = HbcCompiler::new(version)
        .compile(&recovered)
        .map_err(|error| format!("native rebuild: {error}"))?;
    fs::write(&rebuilt_path, rebuilt)
        .map_err(|error| format!("writing rebuilt bytecode: {error}"))?;
    let candidate = execute(hermes, &rebuilt_path, directory.path(), version)?;

    if candidate != reference {
        return Err(format!(
            "execution differs\nreference: {}\nrebuilt:   {}",
            describe(&reference),
            describe(&candidate),
        ));
    }
    Ok(())
}

fn execute(
    hermes: &Path,
    bytecode: &Path,
    temporary_root: &Path,
    version: u32,
) -> Result<Observation, String> {
    let mut runtime = Command::new(hermes);
    if version == 96 {
        runtime.arg("-Xes6-class");
    }
    let output = runtime
        .arg("-b")
        .arg(bytecode)
        .output()
        .map_err(|error| format!("launching Hermes: {error}"))?;
    Ok(observation(output, temporary_root))
}

fn observation(output: Output, temporary_root: &Path) -> Observation {
    Observation {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: normalize_stderr(output.stderr, temporary_root),
    }
}

fn normalize_stderr(stderr: Vec<u8>, temporary_root: &Path) -> Vec<u8> {
    let text = String::from_utf8_lossy(&stderr);
    let text = text
        .replace(&temporary_root.to_string_lossy().into_owned(), "<TMP>")
        .replace("original.hbc", "<HBC>")
        .replace("rebuilt.hbc", "<HBC>");
    let mut normalized = text
        .lines()
        .filter(|line| !line.starts_with("    at "))
        .collect::<Vec<_>>()
        .join("\n");
    if text.ends_with('\n') {
        normalized.push('\n');
    }
    normalized.into_bytes()
}

fn describe(observation: &Observation) -> String {
    format!(
        "status={:?}, stdout={:?}, stderr={:?}",
        observation.code,
        String::from_utf8_lossy(&observation.stdout),
        String::from_utf8_lossy(&observation.stderr),
    )
}

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
};

use mercury_hbc::{
    HbcCompiler,
    binary::{decode_raw_module, parse_hbc_container_with_spec},
    decompile,
    spec_builtin::load_spec,
};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    code: Option<i32>,
    signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Default)]
struct FixtureCoverage {
    reference: BTreeSet<String>,
    rebuilt: BTreeSet<String>,
}

#[derive(Serialize)]
struct CoverageReport {
    version: u32,
    coverage_kind: &'static str,
    successful_cases: usize,
    opcodes: BTreeMap<String, OpcodeCoverage>,
}

#[derive(Serialize)]
struct OpcodeCoverage {
    opcode: u16,
    reference: BTreeMap<String, BTreeSet<String>>,
    rebuilt: BTreeMap<String, BTreeSet<String>>,
}

impl CoverageReport {
    fn new(version: u32) -> Self {
        let spec = load_spec(version).expect("embedded bytecode spec");
        let opcodes = spec
            .bytecode
            .instructions
            .iter()
            .map(|instruction| {
                (
                    instruction.name.clone(),
                    OpcodeCoverage {
                        opcode: instruction.opcode,
                        reference: BTreeMap::new(),
                        rebuilt: BTreeMap::new(),
                    },
                )
            })
            .collect();
        Self {
            version,
            coverage_kind: "static instruction presence after successful roundtrip",
            successful_cases: 0,
            opcodes,
        }
    }

    fn record(&mut self, path: &Path, mode: &str, coverage: FixtureCoverage) {
        self.successful_cases += 1;
        let relative = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(path);
        let fixture = relative.to_string_lossy().into_owned();
        for (reference, opcodes) in [(true, coverage.reference), (false, coverage.rebuilt)] {
            for name in opcodes {
                let entry = self.opcodes.get_mut(&name).expect("decoded opcode in spec");
                let side = if reference {
                    &mut entry.reference
                } else {
                    &mut entry.rebuilt
                };
                side.entry(mode.to_owned())
                    .or_default()
                    .insert(fixture.clone());
            }
        }
    }

    fn write(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create coverage report directory");
        }
        let mut json = serde_json::to_vec_pretty(self).expect("serialize coverage report");
        json.push(b'\n');
        fs::write(path, json).expect("write coverage report");
    }
}

#[test]
fn hbc98_coverage_report_contains_all_opcodes() {
    let spec = load_spec(98).expect("embedded HBC 98 spec");
    let report = CoverageReport::new(98);
    assert_eq!(spec.bytecode.instructions.len(), 219);
    assert_eq!(report.opcodes.len(), 219);
    for instruction in &spec.bytecode.instructions {
        let coverage = report
            .opcodes
            .get(&instruction.name)
            .expect("opcode in coverage report");
        assert_eq!(coverage.opcode, instruction.opcode);
        assert!(coverage.reference.is_empty());
        assert!(coverage.rebuilt.is_empty());
    }
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

/// Fixtures (relative to `tests/corpus`) using syntax the HBC 96 hermesc
/// rejects outright; they only run in the HBC 98 matrix.
const HBC98_ONLY_FIXTURES: &[&str] = &["language/computed_super.js", "language/private_fields.js"];

fn run_corpus(version: u32, runtime_variable: &str) {
    let hermesc = required_tool("HERMESC_BIN", version);
    let hermes = required_tool(runtime_variable, version);
    let corpus_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus");
    let files = corpus_files();
    assert!(!files.is_empty(), "the JavaScript corpus is empty");
    let files = files
        .into_iter()
        .filter(|path| {
            let hbc98_only = HBC98_ONLY_FIXTURES
                .iter()
                .map(Path::new)
                .any(|fixture| path.strip_prefix(&corpus_root) == Ok(fixture));
            if version < 98 && hbc98_only {
                println!("skipping HBC 98-only fixture {}", path.display());
            }
            version >= 98 || !hbc98_only
        })
        .collect::<Vec<_>>();
    let modes = hermesc_modes();

    let mut coverage = CoverageReport::new(version);
    let mut failures = Vec::new();
    for path in &files {
        for mode in &modes {
            match roundtrip_fixture(path, mode, &hermes, &hermesc, version) {
                Ok(fixture_coverage) => coverage.record(path, mode, fixture_coverage),
                Err(error) => failures.push(format!("{} ({mode}):\n{error}", path.display())),
            }
        }
    }

    if let Some(path) = env::var_os("MERCURY_HBC_COVERAGE_REPORT") {
        coverage.write(Path::new(&path));
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
) -> Result<FixtureCoverage, String> {
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
    fs::write(&rebuilt_path, &rebuilt)
        .map_err(|error| format!("writing rebuilt bytecode: {error}"))?;
    let candidate = execute(hermes, &rebuilt_path, directory.path(), version)?;

    if candidate != reference {
        preserve_artifacts(path, optimization, directory.path())?;
        return Err(format!(
            "execution differs\nreference: {}\nrebuilt:   {}",
            describe(&reference),
            describe(&candidate),
        ));
    }
    fixture_coverage(&original_bytes, &rebuilt, version)
}

fn fixture_coverage(
    original: &[u8],
    rebuilt: &[u8],
    version: u32,
) -> Result<FixtureCoverage, String> {
    let spec = load_spec(version).expect("embedded bytecode spec");
    let decode = |bytes: &[u8]| -> Result<BTreeSet<String>, String> {
        let container = parse_hbc_container_with_spec(bytes, &spec.container)
            .map_err(|error| format!("coverage parse: {error}"))?;
        let module = decode_raw_module(&container, bytes, &spec.bytecode)
            .map_err(|error| format!("coverage decode: {error}"))?;
        Ok(module
            .functions
            .iter()
            .flat_map(|function| &function.instructions)
            .map(|instruction| instruction.name.clone())
            .collect())
    };
    Ok(FixtureCoverage {
        reference: decode(original)?,
        rebuilt: decode(rebuilt)?,
    })
}

fn preserve_artifacts(source: &Path, optimization: &str, temporary: &Path) -> Result<(), String> {
    let Some(root) = env::var_os("MERCURY_CORPUS_ARTIFACTS") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    fs::create_dir_all(&root).map_err(|error| format!("creating artifact directory: {error}"))?;
    let stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("corpus");
    let optimization = optimization.trim_start_matches('-');
    for name in ["original.hbc", "rebuilt.hbc"] {
        let destination = root.join(format!("{stem}-{optimization}-{name}"));
        fs::copy(temporary.join(name), &destination)
            .map_err(|error| format!("preserving {}: {error}", destination.display()))?;
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
        signal: termination_signal(&output.status),
        stdout: output.stdout,
        stderr: normalize_stderr(output.stderr, temporary_root),
    }
}

#[cfg(unix)]
fn termination_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn termination_signal(_status: &ExitStatus) -> Option<i32> {
    None
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
        "status={:?}, signal={:?}, stdout={:?}, stderr={:?}",
        observation.code,
        observation.signal,
        String::from_utf8_lossy(&observation.stdout),
        String::from_utf8_lossy(&observation.stderr),
    )
}

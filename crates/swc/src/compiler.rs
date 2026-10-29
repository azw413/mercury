use crate::{Error, SourceKind, SourceLanguage, SwcModule};
use crate::{binary as mercury_binary, spec_builtin as mercury_spec_builtin};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// An adapter for an explicitly configured external `hermesc` executable.
///
/// Use [`HbcCompiler`](crate::HbcCompiler) for the native path with no external
/// tool dependency. This adapter is useful for compatibility testing and for
/// source syntax that Mercury does not lower itself. Compilation never executes
/// the input program; each invocation uses a private temporary directory.
#[derive(Debug, Clone)]
pub struct HermesCompiler {
    executable: PathBuf,
    target_version: u32,
}

impl HermesCompiler {
    /// Creates an adapter for `executable` and an expected HBC `target_version`.
    pub fn new(executable: impl AsRef<Path>, target_version: u32) -> Self {
        Self {
            executable: executable.as_ref().to_owned(),
            target_version,
        }
    }

    /// Prints the module as JavaScript, invokes `hermesc`, and validates its output.
    ///
    /// The compiler runs with optimization, debug output disabled, and Hermes' ES6
    /// class flag enabled. ES modules must be bundled into a script first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Compiler`] when the process cannot run or reports failure,
    /// [`Error::Version`] when its output has an unexpected HBC version, and
    /// [`Error::Io`] for temporary-file failures. Unsupported targets and modules
    /// return [`Error::Unsupported`].
    pub fn compile(&self, module: &SwcModule) -> Result<Vec<u8>, Error> {
        if self.target_version != 96 {
            return Err(Error::Unsupported(
                "the compiler integration currently targets HBC 96".into(),
            ));
        }
        if module.program.is_module() {
            return Err(Error::Unsupported(
                "ES modules must be bundled into a script before Hermes compilation".into(),
            ));
        }
        let javascript = module.javascript();
        // Validate the lowered program as a script; parsing it as a module
        // would impose module strictness on otherwise valid script code.
        SwcModule::parse(
            "lowered.js",
            &javascript,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )?;
        let dir = tempfile::tempdir()?;
        let input = dir.path().join("input.js");
        let output = dir.path().join("output.hbc");
        fs::write(&input, javascript)?;
        let result = Command::new(&self.executable)
            .args(["-Xes6-class", "-O", "-g0", "-emit-binary"])
            .arg(format!("-out={}", output.display()))
            .arg(&input)
            .output()
            .map_err(|err| Error::Compiler(format!("{}: {err}", self.executable.display())))?;
        if !result.status.success() {
            return Err(Error::Compiler(format!(
                "{}: {}",
                result.status,
                String::from_utf8_lossy(&result.stderr)
            )));
        }
        let bytes = fs::read(output)?;
        let actual = bytes
            .get(8..12)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .ok_or_else(|| Error::Bytecode("compiler output has no version header".into()))?;
        if actual != self.target_version {
            return Err(Error::Version {
                expected: self.target_version,
                actual,
            });
        }
        let spec = mercury_spec_builtin::load_spec(actual)
            .ok_or_else(|| Error::Bytecode("missing embedded spec".into()))?;
        mercury_binary::parse_hbc_container_with_spec(&bytes, &spec.container)
            .map_err(|err| Error::Bytecode(err.to_string()))?;
        Ok(bytes)
    }
}

use crate::{Error, SourceKind, SourceLanguage, SwcModule};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// An explicitly configured external compiler. Compilation never executes the
/// input program; every invocation uses a private temporary directory.
pub struct HermesCompiler {
    executable: PathBuf,
    target_version: u32,
}
impl HermesCompiler {
    pub fn new(executable: impl AsRef<Path>, target_version: u32) -> Self {
        Self {
            executable: executable.as_ref().to_owned(),
            target_version,
        }
    }

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

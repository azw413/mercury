use std::process::Command;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
/// Helper for reading files from historical Hermes revisions in a local git checkout.
pub struct HermesSource {
    pub repo_path: String,
}

impl HermesSource {
    /// Creates a new source accessor rooted at the provided repository path.
    pub fn new(repo_path: impl Into<String>) -> Self {
        Self {
            repo_path: repo_path.into(),
        }
    }

    /// Lists git tags available in the configured Hermes checkout.
    pub fn list_tags(&self) -> Result<Vec<String>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_path)
            .arg("tag")
            .output()
            .with_context(|| format!("failed to list git tags in {}", self.repo_path))?;

        if !output.status.success() {
            anyhow::bail!("git tag failed for {}", self.repo_path);
        }

        let stdout = String::from_utf8(output.stdout).context("git tag output was not utf-8")?;
        let mut tags = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        tags.sort();
        Ok(tags)
    }

    /// Reads a single file as it existed at the supplied git tag or revision.
    pub fn read_file_at_tag(&self, tag: &str, path: &str) -> Result<String> {
        let object = format!("{tag}:{path}");
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_path)
            .arg("show")
            .arg(object)
            .output()
            .with_context(|| format!("failed to read {path} at tag {tag}"))?;

        if !output.status.success() {
            anyhow::bail!("git show failed for {tag}:{path}");
        }

        String::from_utf8(output.stdout).context("git show output was not utf-8")
    }
}

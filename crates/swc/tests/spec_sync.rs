use std::{fs, path::PathBuf};

#[test]
fn packaged_specs_match_the_workspace_registry() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.join("../../spec/generated");
    let packaged = manifest.join("spec/generated");
    if !workspace.is_dir() {
        // A crates.io package contains only the packaged registry.
        return;
    }

    let spec_names = |directory: &PathBuf| {
        let mut names = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            .map(|entry| entry.expect("spec entry").file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let workspace_names = spec_names(&workspace);
    let packaged_names = spec_names(&packaged);
    assert!(!workspace_names.is_empty(), "workspace registry must not be empty");
    assert_eq!(packaged_names, workspace_names, "packaged registry filenames differ");

    for name in workspace_names {
        let workspace_spec = workspace.join(&name);
        let packaged_spec = packaged.join(&name);
        assert_eq!(
            fs::read(&packaged_spec).unwrap_or_else(|error| {
                panic!("read {}: {error}", packaged_spec.display())
            }),
            fs::read(&workspace_spec).unwrap_or_else(|error| {
                panic!("read {}: {error}", workspace_spec.display())
            }),
            "packaged spec {} is out of sync; copy spec/generated/*.json into crates/swc/spec/generated/",
            name.to_string_lossy(),
        );
    }
}

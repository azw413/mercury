use mercury_spec::HermesSpec;

/// Embedded JSON payload for one supported Hermes bytecode version.
struct EmbeddedSpec {
    version: u32,
    json: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/registry.rs"));

/// Returns the Hermes bytecode versions embedded into this build.
pub fn supported_versions() -> &'static [u32] {
    SUPPORTED_VERSIONS
}

/// Loads the embedded spec for a specific Hermes bytecode version.
pub fn load_spec(version: u32) -> Option<HermesSpec> {
    let embedded = EMBEDDED_SPECS.iter().find(|spec| spec.version == version)?;
    serde_json::from_slice(embedded.json).ok()
}

/// Deserializes every embedded spec bundled into the current binary.
pub fn load_all_specs() -> Result<Vec<HermesSpec>, serde_json::Error> {
    EMBEDDED_SPECS
        .iter()
        .map(|spec| serde_json::from_slice(spec.json))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_supported_versions_from_embedded_specs() {
        assert!(supported_versions().contains(&89));
        assert!(supported_versions().contains(&94));
        assert!(supported_versions().contains(&96));
    }

    #[test]
    fn loads_embedded_spec_by_version() {
        let spec = load_spec(94).expect("embedded hbc94 spec should exist");
        assert_eq!(spec.bytecode_version, 94);
        assert_eq!(spec.hermes_tag, "1c717488d1799f6153cf6d60c3556ab4ddd9dce6");
    }
}

use anyhow::Result;
use mercury_spec::{
    BytecodeSpec, ContainerSpec, FieldSpec, HermesSpec, InstructionFlags, InstructionOperandSpec,
    InstructionSpec, OperandTypeSpec, SectionSpec, StructSpec,
};

use crate::hermes_source::HermesSource;

#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    pub hermes_repo: String,
}

#[derive(Debug)]
pub struct Extractor {
    source: HermesSource,
}

impl Extractor {
    pub fn new(config: ExtractorConfig) -> Self {
        Self {
            source: HermesSource::new(config.hermes_repo),
        }
    }

    pub fn list_tags(&self) -> Result<Vec<String>> {
        self.source.list_tags()
    }

    pub fn extract_tag(&self, tag: &str) -> Result<HermesSpec> {
        let version_header = self.source.read_file_at_tag(
            tag,
            "include/hermes/BCGen/HBC/BytecodeVersion.h",
        )?;
        let bytecode_list =
            self.source
                .read_file_at_tag(tag, "include/hermes/BCGen/HBC/BytecodeList.def")?;
        let file_format = self.source.read_file_at_tag(
            tag,
            "include/hermes/BCGen/HBC/BytecodeFileFormat.h",
        )?;

        Ok(HermesSpec {
            hermes_tag: tag.to_owned(),
            bytecode_version: parse_bytecode_version(&version_header).unwrap_or_default(),
            bytecode: build_stub_bytecode_spec(&bytecode_list),
            container: build_stub_container_spec(&file_format),
        })
    }
}

fn parse_bytecode_version(source: &str) -> Option<u32> {
    source
        .lines()
        .find_map(|line| line.split("BYTECODE_VERSION = ").nth(1))
        .and_then(|tail| tail.trim_end_matches(';').trim().parse::<u32>().ok())
}

fn build_stub_bytecode_spec(source: &str) -> BytecodeSpec {
    let operand_types = source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("DEFINE_OPERAND_TYPE(") {
                return None;
            }

            let body = line
                .trim_start_matches("DEFINE_OPERAND_TYPE(")
                .trim_end_matches(')');
            let mut parts = body.split(", ");
            let name = parts.next()?.to_owned();
            let rust_like_type = parts.next()?.to_owned();
            Some(OperandTypeSpec {
                name,
                rust_like_type,
            })
        })
        .collect::<Vec<_>>();

    let instructions = source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("DEFINE_OPCODE_") {
                return None;
            }

            let body = line.split_once('(')?.1.trim_end_matches(')');
            let mut parts = body.split(", ");
            let name = parts.next()?.to_owned();
            let operands = parts
                .enumerate()
                .map(|(index, kind)| InstructionOperandSpec {
                    index: index as u8,
                    kind: kind.to_owned(),
                    meaning: None,
                })
                .collect::<Vec<_>>();

            Some((name, operands))
        })
        .enumerate()
        .map(|(opcode, (name, operands))| InstructionSpec {
            opcode: opcode as u16,
            name,
            operands,
            flags: InstructionFlags::default(),
        })
        .collect::<Vec<_>>();

    BytecodeSpec {
        operand_types,
        instructions,
    }
}

fn build_stub_container_spec(source: &str) -> ContainerSpec {
    let file_header = StructSpec {
        name: "BytecodeFileHeader".to_owned(),
        fields: extract_struct_fields(source, "struct BytecodeFileHeader {"),
    };
    let function_header = StructSpec {
        name: "FunctionHeader".to_owned(),
        fields: Vec::new(),
    };

    ContainerSpec {
        magic: "0x1F1903C103BC1FC6".to_owned(),
        delta_magic: "bitwise_not_magic".to_owned(),
        file_header,
        function_header,
        sections: vec![
            SectionSpec {
                name: "file_header".to_owned(),
                alignment: Some(4),
                notes: vec!["first section in the container".to_owned()],
            },
            SectionSpec {
                name: "function_headers".to_owned(),
                alignment: Some(4),
                notes: vec!["follow the file header".to_owned()],
            },
        ],
        notes: vec![
            "initial stub extracted from BytecodeFileFormat.h".to_owned(),
            "function header macro expansion still needs dedicated parsing".to_owned(),
        ],
    }
}

fn extract_struct_fields(source: &str, marker: &str) -> Vec<FieldSpec> {
    let mut in_struct = false;
    let mut fields = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if !in_struct {
            if line == marker {
                in_struct = true;
            }
            continue;
        }

        if line == "};" {
            break;
        }

        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if line.contains('(') || !line.ends_with(';') {
            continue;
        }

        let declaration = line.trim_end_matches(';');
        let mut parts = declaration.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }

        let name = parts.pop().unwrap().trim_end_matches(',');
        let type_name = parts.join(" ");
        fields.push(FieldSpec {
            name: name.to_owned(),
            type_name,
            since_bytecode_version: None,
            notes: Vec::new(),
        });
    }

    fields
}

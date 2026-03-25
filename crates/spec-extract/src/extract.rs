use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use mercury_spec::{
    BitfieldFieldSpec, BitfieldSpec, BuiltinKind, BuiltinSpec, BytecodeSpec, ContainerSpec,
    FieldSpec, HermesSpec, InstructionFlags, InstructionOperandSpec, InstructionSpec,
    OperandMeaning, OperandTypeSpec, RawBufferSpec, RawDebugInfoSpec, RawDebugOffsetsSpec,
    RawExceptionHandlerSpec, RawFooterSpec, RawFunctionBodySpec, RawFunctionHeaderSpec,
    RawFunctionInfoSpec, RawModuleSpec, RawStringTableSpec, RawSubsectionSpec, RawTableSpec,
    SectionSpec, SemanticDebugInfoSpec, SemanticExceptionHandlerSpec, SemanticFieldSpec,
    SemanticFunctionSpec, SemanticInstructionSpec, SemanticModuleSpec, SemanticSideTableSpec,
    SemanticSpec, StructSpec,
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
        let bytecode_stream = self
            .source
            .read_file_at_tag(tag, "lib/BCGen/HBC/BytecodeStream.cpp")?;
        let bytecode_stream_header = self
            .source
            .read_file_at_tag(tag, "include/hermes/BCGen/HBC/BytecodeStream.h")?;
        let builtins = self
            .source
            .read_file_at_tag(tag, "include/hermes/FrontEndDefs/Builtins.def")?;

        Ok(HermesSpec {
            hermes_tag: tag.to_owned(),
            bytecode_version: parse_bytecode_version(&version_header).unwrap_or_default(),
            bytecode: build_stub_bytecode_spec(&bytecode_list, &builtins),
            container: build_stub_container_spec(&file_format, &bytecode_stream, &bytecode_stream_header),
            semantic: build_semantic_spec(),
        })
    }

    pub fn write_json(&self, spec: &HermesSpec, output_path: impl AsRef<Path>) -> Result<()> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }

        let body = serde_json::to_string_pretty(spec).context("failed to serialize spec")?;
        fs::write(output_path, body)
            .with_context(|| format!("failed to write {}", output_path.display()))
    }
}

fn parse_bytecode_version(source: &str) -> Option<u32> {
    source
        .lines()
        .find_map(|line| line.split("BYTECODE_VERSION = ").nth(1))
        .and_then(|tail| tail.trim_end_matches(';').trim().parse::<u32>().ok())
}

fn build_stub_bytecode_spec(source: &str, builtins_source: &str) -> BytecodeSpec {
    let mut instructions = Vec::new();
    let mut operand_meanings = BTreeMap::<(String, u8), OperandMeaning>::new();
    let mut ret_targets = BTreeMap::<String, bool>::new();
    let mut value_buffer_users = BTreeMap::<String, bool>::new();

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

    for line in source.lines() {
        let line = line.trim();

        if line.starts_with("DEFINE_OPCODE_") {
            if let Some((name, operand_kinds)) = parse_instruction_definition(line) {
                let opcode = instructions.len() as u16;
                instructions.push(make_instruction(
                    opcode,
                    name,
                    operand_kinds,
                    InstructionFlags::default(),
                ));
            }
            continue;
        }

        if line.starts_with("DEFINE_JUMP_1(") {
            if let Some(name) = parse_single_name_macro(line, "DEFINE_JUMP_1(") {
                let opcode = instructions.len() as u16;
                instructions.push(make_instruction(
                    opcode,
                    name.clone(),
                    vec!["Addr8".to_owned()],
                    InstructionFlags::default(),
                ));
                instructions.push(make_instruction(
                    opcode + 1,
                    format!("{name}Long"),
                    vec!["Addr32".to_owned()],
                    InstructionFlags {
                        is_jump_long_variant: true,
                        ..InstructionFlags::default()
                    },
                ));
            }
            continue;
        }

        if line.starts_with("DEFINE_JUMP_2(") {
            if let Some(name) = parse_single_name_macro(line, "DEFINE_JUMP_2(") {
                let opcode = instructions.len() as u16;
                instructions.push(make_instruction(
                    opcode,
                    name.clone(),
                    vec!["Addr8".to_owned(), "Reg8".to_owned()],
                    InstructionFlags::default(),
                ));
                instructions.push(make_instruction(
                    opcode + 1,
                    format!("{name}Long"),
                    vec!["Addr32".to_owned(), "Reg8".to_owned()],
                    InstructionFlags {
                        is_jump_long_variant: true,
                        ..InstructionFlags::default()
                    },
                ));
            }
            continue;
        }

        if line.starts_with("DEFINE_JUMP_3(") {
            if let Some(name) = parse_single_name_macro(line, "DEFINE_JUMP_3(") {
                let opcode = instructions.len() as u16;
                instructions.push(make_instruction(
                    opcode,
                    name.clone(),
                    vec!["Addr8".to_owned(), "Reg8".to_owned(), "Reg8".to_owned()],
                    InstructionFlags::default(),
                ));
                instructions.push(make_instruction(
                    opcode + 1,
                    format!("{name}Long"),
                    vec!["Addr32".to_owned(), "Reg8".to_owned(), "Reg8".to_owned()],
                    InstructionFlags {
                        is_jump_long_variant: true,
                        ..InstructionFlags::default()
                    },
                ));
            }
            continue;
        }

        if let Some((name, operand_index, meaning)) = parse_operand_meaning(line) {
            operand_meanings.insert((name, operand_index), meaning);
            continue;
        }

        if let Some(name) = parse_single_name_macro(line, "DEFINE_RET_TARGET(") {
            ret_targets.insert(name, true);
            continue;
        }

        if let Some(name) = parse_single_name_macro(line, "DEFINE_VALUE_BUFFER_USER(") {
            value_buffer_users.insert(name, true);
        }
    }

    for instruction in &mut instructions {
        instruction.flags.has_ret_target = ret_targets.contains_key(&instruction.name);
        instruction.flags.is_value_buffer_user = value_buffer_users.contains_key(&instruction.name);
        for operand in &mut instruction.operands {
            operand.meaning = operand_meanings
                .get(&(instruction.name.clone(), operand.index + 1))
                .cloned();
        }
    }

    BytecodeSpec {
        operand_types,
        instructions,
        builtins: extract_builtins(builtins_source),
    }
}

fn build_stub_container_spec(
    file_format: &str,
    bytecode_stream: &str,
    bytecode_stream_header: &str,
) -> ContainerSpec {
    let magic = file_format
        .lines()
        .find_map(|line| line.trim().strip_prefix("const static uint64_t MAGIC = "))
        .map(|value| value.trim_end_matches(';').to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let delta_magic = file_format
        .lines()
        .find_map(|line| line.trim().strip_prefix("const static uint64_t DELTA_MAGIC = "))
        .map(|value| value.trim_end_matches(';').to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let file_header = StructSpec {
        name: "BytecodeFileHeader".to_owned(),
        fields: extract_struct_fields(file_format, "struct BytecodeFileHeader {"),
    };
    let bytecode_options = extract_bitfield_spec(
        file_format,
        &["union BytecodeOptions {", "struct BytecodeOptions {"],
        "BytecodeOptions",
    );
    let function_header_flags = extract_bitfield_spec(
        file_format,
        &["union FunctionHeaderFlag {", "struct FunctionHeaderFlag {"],
        "FunctionHeaderFlag",
    );
    let function_header = StructSpec {
        name: "FunctionHeader".to_owned(),
        fields: {
            let mut fields = extract_function_header_fields(file_format);
            fields.push(FieldSpec {
                name: "flags".to_owned(),
                type_name: "FunctionHeaderFlag".to_owned(),
                since_bytecode_version: None,
                notes: Vec::new(),
            });
            fields
        },
    };

    ContainerSpec {
        magic,
        delta_magic,
        bytecode_options,
        file_header,
        function_header_flags,
        function_header,
        raw_module: build_raw_module_spec(file_format, bytecode_stream, bytecode_stream_header),
        sections: extract_container_sections(file_format, bytecode_stream),
        notes: vec![
            "container sections are derived from visitBytecodeSegmentsInOrder and BytecodeSerializer::serialize".to_owned(),
        ],
    }
}

fn build_raw_module_spec(
    file_format: &str,
    bytecode_stream: &str,
    bytecode_stream_header: &str,
) -> RawModuleSpec {
    let info_alignment = extract_const_u32(bytecode_stream_header, "INFO_ALIGNMENT")
        .or_else(|| extract_const_u32(bytecode_stream, "INFO_ALIGNMENT"));

    RawModuleSpec {
        function_header: RawFunctionHeaderSpec {
            small_header_fields: extract_function_header_fields(file_format),
            small_header_flags: "FunctionHeaderFlag".to_owned(),
            large_header_fields: {
                let mut fields = extract_function_header_fields(file_format);
                fields.push(FieldSpec {
                    name: "flags".to_owned(),
                    type_name: "FunctionHeaderFlag".to_owned(),
                    since_bytecode_version: None,
                    notes: Vec::new(),
                });
                fields
            },
            overflow_strategy:
                "SmallFuncHeader either stores compact fields directly or encodes a large header offset when flags.overflowed is set"
                    .to_owned(),
        },
        function_body: RawFunctionBodySpec {
            opcode_stream_alignment: None,
            jump_table_alignment: Some(4),
            jump_tables_inlined_after_opcodes: true,
            optional_padding_control: Some("BytecodeGenerationOptions::padFunctionBodiesPercent".to_owned()),
            notes: vec![
                "function bytecode may be deduplicated during layout".to_owned(),
                "opcode bytes are serialized first; jump tables follow after 4-byte alignment".to_owned(),
            ],
        },
        function_info: RawFunctionInfoSpec {
            info_alignment,
            large_header_may_be_present: true,
            subsections: vec![
                RawSubsectionSpec {
                    name: "large_function_header".to_owned(),
                    alignment: info_alignment,
                    storage: "FunctionHeader".to_owned(),
                    notes: vec!["present only when SmallFuncHeader overflows".to_owned()],
                },
                RawSubsectionSpec {
                    name: "exception_handler_table".to_owned(),
                    alignment: info_alignment,
                    storage: "ExceptionHandlerTableHeader + HBCExceptionHandlerInfo[]".to_owned(),
                    notes: vec!["present only when the function has exception handlers".to_owned()],
                },
                RawSubsectionSpec {
                    name: "debug_offsets".to_owned(),
                    alignment: info_alignment,
                    storage: "DebugOffsets".to_owned(),
                    notes: vec!["present only when debug info is not stripped and the function has debug info".to_owned()],
                },
            ],
            notes: vec![
                "function info is serialized after all function bodies".to_owned(),
                "BF.infoOffset points to the start of this aligned info block".to_owned(),
            ],
        },
        exception_handlers: RawExceptionHandlerSpec {
            header_name: "ExceptionHandlerTableHeader".to_owned(),
            table_entry_type: "HBCExceptionHandlerInfo".to_owned(),
            alignment: info_alignment,
            notes: vec!["serialized within the function info area".to_owned()],
        },
        debug_offsets: RawDebugOffsetsSpec {
            record_type: "DebugOffsets".to_owned(),
            alignment: info_alignment,
            notes: vec!["serialized within the function info area".to_owned()],
        },
        debug_info: RawDebugInfoSpec {
            header_name: "DebugInfoHeader".to_owned(),
            alignment: Some(4),
            subsections: vec![
                RawSubsectionSpec {
                    name: "filename_table".to_owned(),
                    alignment: None,
                    storage: "StringTableEntry[]".to_owned(),
                    notes: Vec::new(),
                },
                RawSubsectionSpec {
                    name: "filename_storage".to_owned(),
                    alignment: None,
                    storage: "u8[]".to_owned(),
                    notes: Vec::new(),
                },
                RawSubsectionSpec {
                    name: "file_regions".to_owned(),
                    alignment: None,
                    storage: "DebugFileRegion[]".to_owned(),
                    notes: Vec::new(),
                },
                RawSubsectionSpec {
                    name: "debug_data".to_owned(),
                    alignment: None,
                    storage: "u8[]".to_owned(),
                    notes: vec!["contains source locations and lexical data; lexicalDataOffset points into this blob".to_owned()],
                },
            ],
            strip_behavior: Some("when stripDebugInfoSection is enabled, an empty DebugInfoHeader is still serialized".to_owned()),
            notes: vec!["debugInfoOffset in the file header points here".to_owned()],
        },
        string_table: RawStringTableSpec {
            small_entry_type: "SmallStringTableEntry".to_owned(),
            overflow_entry_type: "OverflowStringTableEntry".to_owned(),
            overflow_strategy:
                "small entries mark overflowed offset/length and reference overflow table indices"
                    .to_owned(),
            notes: vec!["string storage is serialized separately as a raw blob".to_owned()],
        },
        array_buffer: RawBufferSpec {
            alignment: Some(4),
            storage: "u8[]".to_owned(),
            notes: vec!["serialized literal array buffer".to_owned()],
        },
        object_key_buffer: RawBufferSpec {
            alignment: Some(4),
            storage: "u8[]".to_owned(),
            notes: vec!["first half of BytecodeModule object buffer pair".to_owned()],
        },
        object_value_buffer: RawBufferSpec {
            alignment: Some(4),
            storage: "u8[]".to_owned(),
            notes: vec!["second half of BytecodeModule object buffer pair".to_owned()],
        },
        bigint_table: RawTableSpec {
            alignment: Some(4),
            entry_type: "BigIntTableEntry".to_owned(),
            storage: "table + separate bigint storage blob".to_owned(),
            notes: Vec::new(),
        },
        regexp_table: RawTableSpec {
            alignment: Some(4),
            entry_type: "RegExpTableEntry".to_owned(),
            storage: "table + separate regexp storage blob".to_owned(),
            notes: Vec::new(),
        },
        cjs_module_table: RawTableSpec {
            alignment: Some(4),
            entry_type: "pair<uint32_t, uint32_t> or static module entry".to_owned(),
            storage: "dynamic pairs or static table depending on bytecode options".to_owned(),
            notes: Vec::new(),
        },
        function_source_table: RawTableSpec {
            alignment: Some(4),
            entry_type: "pair<uint32_t, uint32_t>".to_owned(),
            storage: "function source table entries mapping function id to string id".to_owned(),
            notes: Vec::new(),
        },
        footer: RawFooterSpec {
            type_name: "BytecodeFileFooter".to_owned(),
            hash_description: "SHA1 of all bytes above the footer".to_owned(),
            notes: vec!["serialized even during layout, with a zero/ignored hash until the final pass".to_owned()],
        },
    }
}

fn build_semantic_spec() -> SemanticSpec {
    SemanticSpec {
        module: SemanticModuleSpec {
            fields: vec![
                semantic_field("functions", "Vec<Function>", "normalized from function headers + bodies"),
                semantic_field("entry_function", "FunctionId", "globalCodeIndex in file header"),
                semantic_field("strings", "StringTable", "normalized from small/overflow string tables + storage"),
                semantic_field("bigints", "BigIntTable", "normalized from bigint table + storage"),
                semantic_field("regexps", "RegExpTable", "normalized from regexp table + storage"),
                semantic_field("builtins", "Vec<BuiltinRef>", "normalized from Builtins.def"),
                semantic_field("cjs_modules", "CjsModuleTable", "normalized from cjs module section"),
            ],
            notes: vec![
                "module is the stable semantic root over the raw container".to_owned(),
                "semantic module intentionally hides alignment, padding, and overflow-header details".to_owned(),
            ],
        },
        function: SemanticFunctionSpec {
            fields: vec![
                semantic_field("id", "FunctionId", "position in function table"),
                semantic_field("name", "StringId", "functionName in function header"),
                semantic_field("parameters", "u32", "paramCount in function header"),
                semantic_field("frame_size", "u32", "frameSize in function header"),
                semantic_field("environment_size", "u32", "environmentSize in function header"),
                semantic_field("flags", "FunctionFlags", "normalized from FunctionHeaderFlag"),
                semantic_field("instructions", "Vec<Instruction>", "decoded from function bytecode"),
                semantic_field("jump_tables", "Vec<JumpTable>", "decoded from trailing jump-table area"),
                semantic_field("exception_handlers", "Vec<ExceptionHandler>", "decoded from function info"),
                semantic_field("debug_offsets", "Option<DebugOffsets>", "decoded from function info"),
            ],
            notes: vec![
                "semantic function is intended to remain mostly stable across bytecode versions".to_owned(),
            ],
        },
        instruction: SemanticInstructionSpec {
            fields: vec![
                semantic_field("offset", "u32", "byte offset within function body"),
                semantic_field("opcode", "OpcodeId", "decoded from bytecode stream"),
                semantic_field("mnemonic", "String", "instruction metadata name"),
                semantic_field("operands", "Vec<Operand>", "decoded and typed via bytecode spec"),
                semantic_field("branch_targets", "Vec<InstructionOffset>", "normalized from jump operands and switch tables"),
            ],
            notes: vec![
                "semantic instruction is normalized over short/long encoding details where practical".to_owned(),
            ],
        },
        exception_handler: SemanticExceptionHandlerSpec {
            fields: vec![
                semantic_field("start", "InstructionOffset", "HBCExceptionHandlerInfo.start"),
                semantic_field("end", "InstructionOffset", "HBCExceptionHandlerInfo.end"),
                semantic_field("target", "InstructionOffset", "HBCExceptionHandlerInfo.target"),
            ],
            notes: vec!["exception handlers are function-local semantic ranges".to_owned()],
        },
        debug_info: SemanticDebugInfoSpec {
            fields: vec![
                semantic_field("source_locations", "Vec<SourceLocation>", "decoded from DebugInfo data blob"),
                semantic_field("lexical_data", "LexicalData", "decoded from DebugInfo data blob using lexicalDataOffset"),
                semantic_field("file_regions", "Vec<FileRegion>", "DebugFileRegion entries"),
                semantic_field("filenames", "StringTable", "filename table + filename storage"),
            ],
            notes: vec![
                "semantic debug info hides the packed file format and offset indirections".to_owned(),
            ],
        },
        side_tables: vec![
            SemanticSideTableSpec {
                name: "StringTable".to_owned(),
                fields: vec![
                    semantic_field("entries", "Vec<StringEntry>", "small/overflow string tables + string storage"),
                ],
                notes: Vec::new(),
            },
            SemanticSideTableSpec {
                name: "BigIntTable".to_owned(),
                fields: vec![
                    semantic_field("entries", "Vec<BigIntEntry>", "bigint table + bigint storage"),
                ],
                notes: Vec::new(),
            },
            SemanticSideTableSpec {
                name: "RegExpTable".to_owned(),
                fields: vec![
                    semantic_field("entries", "Vec<RegExpEntry>", "regexp table + regexp storage"),
                ],
                notes: Vec::new(),
            },
            SemanticSideTableSpec {
                name: "CjsModuleTable".to_owned(),
                fields: vec![
                    semantic_field("entries", "Vec<CjsModuleEntry>", "dynamic or static cjs module section"),
                ],
                notes: Vec::new(),
            },
        ],
        notes: vec![
            "semantic layer is analysis-facing and should be more stable across bytecode versions than the raw container".to_owned(),
            "this layer is currently a target schema; full population will come with binary parsing and lifting".to_owned(),
        ],
    }
}

fn make_instruction(
    opcode: u16,
    name: String,
    operand_kinds: Vec<String>,
    flags: InstructionFlags,
) -> InstructionSpec {
    let operands = operand_kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| InstructionOperandSpec {
            index: index as u8,
            kind,
            meaning: None,
        })
        .collect::<Vec<_>>();

    InstructionSpec {
        opcode,
        name,
        operands,
        flags,
    }
}

fn parse_instruction_definition(line: &str) -> Option<(String, Vec<String>)> {
    let body = line.split_once('(')?.1.trim_end_matches(')');
    let mut parts = body.split(", ");
    let name = parts.next()?.to_owned();
    if name == "name" || name.contains("##") {
        return None;
    }
    let operands = parts.map(ToOwned::to_owned).collect::<Vec<_>>();
    Some((name, operands))
}

fn parse_single_name_macro(line: &str, prefix: &str) -> Option<String> {
    if !line.starts_with(prefix) {
        return None;
    }

    Some(
        line.trim_start_matches(prefix)
            .trim_end_matches(')')
            .trim()
            .to_owned(),
    )
}

fn parse_operand_meaning(line: &str) -> Option<(String, u8, OperandMeaning)> {
    for (prefix, meaning) in [
        ("OPERAND_BIGINT_ID(", OperandMeaning::BigIntId),
        ("OPERAND_FUNCTION_ID(", OperandMeaning::FunctionId),
        ("OPERAND_STRING_ID(", OperandMeaning::StringId),
    ] {
        if let Some(body) = line.strip_prefix(prefix) {
            let mut parts = body.trim_end_matches(')').split(", ");
            let name = parts.next()?.to_owned();
            let operand_index = parts.next()?.parse::<u8>().ok()?;
            return Some((name, operand_index, meaning));
        }
    }

    None
}

fn extract_builtins(source: &str) -> Vec<BuiltinSpec> {
    let mut builtins = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        let parsed = if let Some(body) = line.strip_prefix("BUILTIN_OBJECT(") {
            Some((BuiltinKind::BuiltinObject, body.trim_end_matches(')').to_owned()))
        } else if let Some(body) = line.strip_prefix("BUILTIN_METHOD(") {
            Some((
                BuiltinKind::BuiltinMethod,
                body.trim_end_matches(')').replace(", ", "."),
            ))
        } else if let Some(body) = line.strip_prefix("PRIVATE_BUILTIN(") {
            Some((BuiltinKind::PrivateBuiltin, body.trim_end_matches(')').to_owned()))
        } else if let Some(body) = line.strip_prefix("JS_BUILTIN(") {
            Some((BuiltinKind::JsBuiltin, body.trim_end_matches(')').to_owned()))
        } else {
            None
        };

        if let Some((kind, name)) = parsed {
            builtins.push(BuiltinSpec {
                index: builtins.len() as u32,
                kind,
                name,
            });
        }
    }

    builtins
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

        let declaration = line
            .split("//")
            .next()
            .map(str::trim)
            .unwrap_or_default();

        if declaration.is_empty() || declaration.contains('(') || !declaration.ends_with(';') {
            continue;
        }

        let declaration = declaration.trim_end_matches(';');
        let mut parts = declaration.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }

        let raw_name = parts.pop().unwrap().trim_end_matches(',');
        let name = raw_name.split('[').next().unwrap_or(raw_name);
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

fn extract_function_header_fields(source: &str) -> Vec<FieldSpec> {
    let mut in_macro = false;
    let mut fields = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if !in_macro {
            if line.starts_with("#define FUNC_HEADER_FIELDS(") {
                in_macro = true;
            }
            continue;
        }

        let line = line.split("//").next().map(str::trim).unwrap_or_default();
        if line.is_empty() {
            continue;
        }

        let has_continuation = line.ends_with('\\');
        let trimmed = line.trim_end_matches('\\').trim();
        let body = if let Some(body) = trimmed.strip_prefix("V(") {
            body
        } else if let Some(body) = trimmed
            .strip_prefix("F(")
            .or_else(|| trimmed.strip_prefix("N("))
        {
            body
        } else {
            if !has_continuation {
                break;
            }
            continue;
        };

        let parts = body.trim_end_matches(')').split(", ").collect::<Vec<_>>();
        let (type_name, name, bits) = match parts.as_slice() {
            [api_type, _store_type, name, bits] => (*api_type, *name, *bits),
            [_first_name, _storage_name, api_type, name, bits] => (*api_type, *name, *bits),
            _ => continue,
        };
        fields.push(FieldSpec {
            name: name.to_owned(),
            type_name: type_name.to_owned(),
            since_bytecode_version: None,
            notes: vec![format!("bit_width={bits}")],
        });

        if !has_continuation {
            break;
        }
    }

    fields
}

fn extract_bitfield_spec(source: &str, markers: &[&str], name: &str) -> BitfieldSpec {
    let mut in_union = false;
    let mut in_struct = false;
    let mut saw_struct = false;
    let mut fields = Vec::new();

    for line in source.lines() {
        let line = line.trim();
        if !in_union {
            if markers.iter().any(|marker| line == *marker) {
                in_union = true;
            }
            continue;
        }

        if !in_struct {
            if line == "struct {" {
                in_struct = true;
                saw_struct = true;
            } else if line == "};" && saw_struct {
                break;
            }
            continue;
        }

        if line == "};" {
            in_struct = false;
            continue;
        }

        if line.is_empty() || line.starts_with("///") {
            continue;
        }

        if let Some(field) = parse_bitfield_macro_line(line) {
            fields.push(field);
            continue;
        }

        let declaration = line
            .split("//")
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .trim_end_matches(';');
        if !declaration.contains(':') {
            continue;
        }

        let mut sides = declaration.split(':');
        let left = sides.next().unwrap_or_default().trim();
        let bit_width = sides
            .next()
            .and_then(|value| value.trim().parse::<u8>().ok())
            .unwrap_or(0);
        let mut left_parts = left.split_whitespace().collect::<Vec<_>>();
        if left_parts.len() < 2 {
            continue;
        }
        let field_name = left_parts.pop().unwrap().to_owned();
        let type_name = left_parts.join(" ");
        fields.push(BitfieldFieldSpec {
            name: field_name,
            type_name,
            bit_width,
            notes: Vec::new(),
        });
    }

    BitfieldSpec {
        name: name.to_owned(),
        fields,
    }
}

fn parse_bitfield_macro_line(line: &str) -> Option<BitfieldFieldSpec> {
    let body = if let Some(body) = line.strip_prefix("HERMES_FIRST_BITFIELD(") {
        body.trim_end_matches(");")
    } else if let Some(body) = line.strip_prefix("HERMES_NEXT_BITFIELD(") {
        body.trim_end_matches(");")
    } else {
        return None;
    };

    let parts = body.split(", ").collect::<Vec<_>>();
    let (type_name, field_name, bit_width) = match parts.as_slice() {
        [_, _, api_type, name, bits] => (*api_type, *name, *bits),
        _ => return None,
    };

    Some(BitfieldFieldSpec {
        name: field_name.to_owned(),
        type_name: type_name.to_owned(),
        bit_width: bit_width.parse::<u8>().ok()?,
        notes: Vec::new(),
    })
}

fn extract_container_sections(file_format: &str, bytecode_stream: &str) -> Vec<SectionSpec> {
    let mut sections = Vec::new();

    sections.push(SectionSpec {
        name: "file_header".to_owned(),
        alignment: Some(4),
        notes: vec!["serialized first via writeBinary(BytecodeFileHeader)".to_owned()],
    });

    let mut in_visit = false;
    for line in file_format.lines() {
        let line = line.trim();
        if !in_visit {
            if line.starts_with("void visitBytecodeSegmentsInOrder(") {
                in_visit = true;
            }
            continue;
        }

        if line == "}" {
            break;
        }

        let Some(method_name) = line
            .strip_prefix("visitor.")
            .and_then(|rest| rest.strip_suffix("();"))
        else {
            continue;
        };

        let (name, notes) = map_visit_method_to_section(method_name);
        sections.push(SectionSpec {
            name: name.to_owned(),
            alignment: Some(4),
            notes,
        });
    }

    sections.push(SectionSpec {
        name: "function_bodies".to_owned(),
        alignment: None,
        notes: vec![
            "serialized after the template-driven segments".to_owned(),
            "jump tables are aligned to 4 bytes after opcode blocks".to_owned(),
            "optional body padding may be emitted when padFunctionBodiesPercent is enabled".to_owned(),
        ],
    });
    sections.push(SectionSpec {
        name: "function_info".to_owned(),
        alignment: Some(4),
        notes: vec![
            "contains overflowed large headers when needed".to_owned(),
            "contains exception handler tables and debug offsets".to_owned(),
            "subsections use INFO_ALIGNMENT = 4".to_owned(),
        ],
    });
    sections.push(SectionSpec {
        name: "debug_info".to_owned(),
        alignment: Some(4),
        notes: vec![
            "debugInfoOffset points here".to_owned(),
            "serialized even in stripped mode as an empty DebugInfoHeader".to_owned(),
        ],
    });
    sections.push(SectionSpec {
        name: "file_footer".to_owned(),
        alignment: None,
        notes: vec!["contains the SHA1 file hash of everything above the footer".to_owned()],
    });

    if bytecode_stream.contains("pad(INFO_ALIGNMENT);") {
        for section in &mut sections {
            if section.name == "function_info" {
                section
                    .notes
                    .push("serializer pads exception/debug-info subsections to INFO_ALIGNMENT".to_owned());
            }
        }
    }

    sections
}

fn extract_const_u32(source: &str, const_name: &str) -> Option<u32> {
    source.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("static constexpr ") || !line.contains(const_name) {
            return None;
        }

        let (lhs, rhs) = line.split_once('=')?;
        let lhs = lhs.trim();
        if !lhs.split_whitespace().any(|part| part == const_name) {
            return None;
        }

        rhs.trim_end_matches(';').trim().parse::<u32>().ok()
    })
}

fn semantic_field(name: &str, type_name: &str, source: &str) -> SemanticFieldSpec {
    SemanticFieldSpec {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        source: source.to_owned(),
        notes: Vec::new(),
    }
}

fn map_visit_method_to_section(method_name: &str) -> (&'static str, Vec<String>) {
    match method_name {
        "visitFunctionHeaders" => (
            "function_headers",
            vec!["serialized as SmallFuncHeader entries".to_owned()],
        ),
        "visitStringKinds" => (
            "string_kinds",
            vec!["run-length encoded string kind table".to_owned()],
        ),
        "visitIdentifierHashes" => (
            "identifier_hashes",
            vec!["identifier hash array".to_owned()],
        ),
        "visitSmallStringTable" => (
            "small_string_table",
            vec!["includes overflow markers pointing into overflow_string_table".to_owned()],
        ),
        "visitOverflowStringTable" => (
            "overflow_string_table",
            vec!["present when small string table entries overflow offset or length".to_owned()],
        ),
        "visitStringStorage" => ("string_storage", vec!["raw string blob".to_owned()]),
        "visitArrayBuffer" => ("array_buffer", vec!["serialized literal array buffer".to_owned()]),
        "visitObjectKeyBuffer" => (
            "object_key_buffer",
            vec!["object key literal buffer".to_owned()],
        ),
        "visitObjectValueBuffer" => (
            "object_value_buffer",
            vec!["object value literal buffer".to_owned()],
        ),
        "visitBigIntTable" => ("bigint_table", vec!["bigint table entries".to_owned()]),
        "visitBigIntStorage" => ("bigint_storage", vec!["bigint storage blob".to_owned()]),
        "visitRegExpTable" => ("regexp_table", vec!["regexp table entries".to_owned()]),
        "visitRegExpStorage" => ("regexp_storage", vec!["regexp bytecode blob".to_owned()]),
        "visitCJSModuleTable" => (
            "cjs_module_table",
            vec!["dynamic pairs or static table depending on bytecode options".to_owned()],
        ),
        "visitFunctionSourceTable" => (
            "function_source_table",
            vec!["preserved function source references".to_owned()],
        ),
        _ => ("unknown_segment", vec![format!("unrecognized serializer visit method: {method_name}")]),
    }
}

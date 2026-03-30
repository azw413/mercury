use crate::encode::{encode_instructions, HbcEncodeError};
use crate::functions::{
    write_small_function_header, FunctionHeader, FunctionHeaderFlags,
};
use crate::header::{
    write_file_header, BytecodeOptions, HbcVersionedFileHeader, FILE_HEADER_SIZE, HERMES_MAGIC,
};
use crate::tables::{
    write_overflow_string_table_entries, write_shape_table_entries, write_small_string_table_entries,
    write_string_kind_entries, OverflowStringTableEntry, ShapeTableEntry, SmallStringTableEntry,
    StringKind, StringKindEntry,
};
use crate::{DecodedInstruction, DecodedOperand};
use mercury_spec::BytecodeSpec;
use sha1::{Digest, Sha1};
use thiserror::Error;

const SMALL_FUNCTION_HEADER_SIZE: usize = 16;
const BYTECODE_ALIGNMENT: usize = 4;
const FOOTER_SIZE: usize = 20;
const SMALL_STRING_MAX_OFFSET: u32 = (1 << 23) - 1;
const SMALL_STRING_MAX_LENGTH: u32 = 0xff - 1;

#[derive(Debug, Clone, PartialEq)]
pub struct MinimalModule {
    pub version: u32,
    pub global_code_index: u32,
    pub strings: Vec<String>,
    pub string_kinds: Vec<StringKind>,
    pub literal_value_buffer: Vec<u8>,
    pub object_key_buffer: Vec<u8>,
    pub object_shape_table: Vec<ShapeTableEntry>,
    pub functions: Vec<MinimalFunction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinimalFunction {
    pub name: String,
    pub param_count: u32,
    pub frame_size: u32,
    pub environment_size: u32,
    pub instructions: Vec<DecodedInstruction>,
}

#[derive(Debug, Error)]
pub enum HbcBuildError {
    #[error("only bytecode version 96 is currently supported for semantic module building")]
    UnsupportedVersion,
    #[error("instruction encoding failed")]
    Encode(#[from] HbcEncodeError),
    #[error("too many strings for a minimal module: {count}")]
    TooManyStrings { count: usize },
    #[error("too many functions for a minimal module: {count}")]
    TooManyFunctions { count: usize },
    #[error("function header field overflow for function {function}")]
    FunctionHeaderOverflow { function: String },
    #[error("instruction references missing string id {string_id} in function {function}")]
    MissingString { function: String, string_id: u32 },
}

pub fn build_minimal_module(
    module: &MinimalModule,
    bytecode_spec: &BytecodeSpec,
) -> Result<Vec<u8>, HbcBuildError> {
    if module.version != 96 {
        return Err(HbcBuildError::UnsupportedVersion);
    }

    if module.functions.len() > u32::MAX as usize {
        return Err(HbcBuildError::TooManyFunctions {
            count: module.functions.len(),
        });
    }

    let mut string_pool = module.strings.clone();
    let mut string_kinds = module.string_kinds.clone();
    let mut function_name_ids = Vec::with_capacity(module.functions.len());
    for function in &module.functions {
        function_name_ids.push(intern_string_with_kind(
            &mut string_pool,
            &mut string_kinds,
            &function.name,
            StringKind::String,
        ));
    }
    if string_pool.len() > u32::MAX as usize {
        return Err(HbcBuildError::TooManyStrings {
            count: string_pool.len(),
        });
    }

    let encoded_bodies = module
        .functions
        .iter()
        .map(|function| encode_instructions(&function.instructions, bytecode_spec))
        .collect::<Result<Vec<_>, _>>()?;

    let string_kinds = if string_kinds.len() == string_pool.len() {
        string_kinds
    } else {
        classify_string_kinds(module, &string_pool)?
    };
    let identifier_hashes = build_identifier_hashes(&string_pool, &string_kinds);
    let string_table = build_string_tables(&string_pool);

    let function_headers_start = FILE_HEADER_SIZE;
    let function_headers_end =
        function_headers_start + module.functions.len() * SMALL_FUNCTION_HEADER_SIZE;
    let string_kinds_start = align_up(function_headers_end, BYTECODE_ALIGNMENT);
    let string_kinds_bytes = write_string_kind_entries(&encode_string_kind_entries(&string_kinds));
    let identifier_hashes_start = align_up(string_kinds_start + string_kinds_bytes.len(), BYTECODE_ALIGNMENT);
    let identifier_hashes_bytes = write_u32_array(&identifier_hashes);
    let small_string_table_start =
        align_up(identifier_hashes_start + identifier_hashes_bytes.len(), BYTECODE_ALIGNMENT);
    let small_string_table_bytes =
        write_small_string_table_entries(&string_table.small_entries);
    let overflow_string_table_start =
        align_up(small_string_table_start + small_string_table_bytes.len(), BYTECODE_ALIGNMENT);
    let overflow_string_table_bytes =
        write_overflow_string_table_entries(&string_table.overflow_entries);
    let string_storage_start =
        align_up(overflow_string_table_start + overflow_string_table_bytes.len(), BYTECODE_ALIGNMENT);
    let string_storage_bytes = string_table.storage;
    let literal_value_buffer_start =
        align_up(string_storage_start + string_storage_bytes.len(), BYTECODE_ALIGNMENT);
    let literal_value_buffer_bytes = module.literal_value_buffer.clone();
    let object_key_buffer_start =
        align_up(literal_value_buffer_start + literal_value_buffer_bytes.len(), BYTECODE_ALIGNMENT);
    let object_key_buffer_bytes = module.object_key_buffer.clone();
    let object_shape_table_start =
        align_up(object_key_buffer_start + object_key_buffer_bytes.len(), BYTECODE_ALIGNMENT);
    let object_shape_table_bytes = write_shape_table_entries(&module.object_shape_table);
    let function_bodies_start =
        align_up(object_shape_table_start + object_shape_table_bytes.len(), BYTECODE_ALIGNMENT);

    let function_headers = build_function_headers(
        module,
        &function_name_ids,
        &encoded_bodies,
        function_bodies_start,
    )?;

    let mut bytes = Vec::new();
    bytes.resize(FILE_HEADER_SIZE, 0);

    for header in &function_headers {
        bytes.extend_from_slice(&write_small_function_header(header));
    }

    pad_to(&mut bytes, string_kinds_start);
    bytes.extend_from_slice(&string_kinds_bytes);
    pad_to(&mut bytes, identifier_hashes_start);
    bytes.extend_from_slice(&identifier_hashes_bytes);
    pad_to(&mut bytes, small_string_table_start);
    bytes.extend_from_slice(&small_string_table_bytes);
    pad_to(&mut bytes, overflow_string_table_start);
    bytes.extend_from_slice(&overflow_string_table_bytes);
    pad_to(&mut bytes, string_storage_start);
    bytes.extend_from_slice(&string_storage_bytes);
    pad_to(&mut bytes, literal_value_buffer_start);
    bytes.extend_from_slice(&literal_value_buffer_bytes);
    pad_to(&mut bytes, object_key_buffer_start);
    bytes.extend_from_slice(&object_key_buffer_bytes);
    pad_to(&mut bytes, object_shape_table_start);
    bytes.extend_from_slice(&object_shape_table_bytes);
    pad_to(&mut bytes, function_bodies_start);

    for body in &encoded_bodies {
        bytes.extend_from_slice(body);
    }

    let debug_info_offset = align_up(bytes.len(), BYTECODE_ALIGNMENT);
    pad_to(&mut bytes, debug_info_offset);
    bytes.extend_from_slice(&empty_debug_info_section(module.version));

    let footer_hash = compute_sha1(&bytes);
    bytes.extend_from_slice(&footer_hash);

    let header = HbcVersionedFileHeader {
        magic: HERMES_MAGIC,
        version: module.version,
        source_hash: [0u8; 20],
        file_length: bytes.len() as u32,
        global_code_index: module.global_code_index,
        function_count: module.functions.len() as u32,
        string_kind_count: count_runs(&string_kinds) as u32,
        identifier_count: identifier_hashes.len() as u32,
        string_count: string_pool.len() as u32,
        overflow_string_count: string_table.overflow_entries.len() as u32,
        string_storage_size: string_storage_bytes.len() as u32,
        big_int_count: 0,
        big_int_storage_size: 0,
        reg_exp_count: 0,
        reg_exp_storage_size: 0,
        literal_value_buffer_size: literal_value_buffer_bytes.len() as u32,
        obj_key_buffer_size: object_key_buffer_bytes.len() as u32,
        obj_shape_table_count: module.object_shape_table.len() as u32,
        num_string_switch_imms: 0,
        segment_id: 0,
        cjs_module_count: 0,
        function_source_count: 0,
        debug_info_offset: debug_info_offset as u32,
        options: BytecodeOptions {
            raw: 0,
            static_builtins: false,
            cjs_modules_statically_resolved: false,
            has_async: false,
        },
    };
    bytes[0..FILE_HEADER_SIZE].copy_from_slice(&write_file_header(&header));

    Ok(bytes)
}

struct BuiltStringTable {
    small_entries: Vec<SmallStringTableEntry>,
    overflow_entries: Vec<OverflowStringTableEntry>,
    storage: Vec<u8>,
}

fn build_function_headers(
    module: &MinimalModule,
    function_name_ids: &[u32],
    encoded_bodies: &[Vec<u8>],
    function_bodies_start: usize,
) -> Result<Vec<FunctionHeader>, HbcBuildError> {
    let mut headers = Vec::with_capacity(module.functions.len());
    let mut body_offset = function_bodies_start as u32;

    for ((function, function_name), body) in module
        .functions
        .iter()
        .zip(function_name_ids.iter().copied())
        .zip(encoded_bodies.iter())
    {
        let read_cache = highest_cache_index(body, &function.instructions, true);
        let write_cache = highest_cache_index(body, &function.instructions, false);
        let header = FunctionHeader {
            offset: body_offset,
            param_count: function.param_count,
            bytecode_size_in_bytes: body.len() as u32,
            function_name,
            info_offset: 0,
            frame_size: function.frame_size,
            environment_size: function.environment_size,
            highest_read_cache_index: read_cache,
            highest_write_cache_index: write_cache,
            flags: FunctionHeaderFlags {
                raw: 0,
                prohibit_invoke: 2,
                strict_mode: false,
                has_exception_handler: false,
                has_debug_info: false,
                overflowed: false,
            },
            overflowed_from_small_header: false,
        };

        ensure_small_header_fits(&header).ok_or_else(|| HbcBuildError::FunctionHeaderOverflow {
            function: function.name.clone(),
        })?;

        headers.push(header);
        body_offset = body_offset.saturating_add(body.len() as u32);
    }

    Ok(headers)
}

fn highest_cache_index(_body: &[u8], instructions: &[DecodedInstruction], read: bool) -> u8 {
    instructions
        .iter()
        .filter_map(|instruction| cache_index_for_instruction(instruction, read))
        .max()
        .unwrap_or(0)
}

fn cache_index_for_instruction(instruction: &DecodedInstruction, read: bool) -> Option<u8> {
    match instruction.name.as_str() {
        "GetByIdShort" | "GetById" | "GetByIdLong" | "TryGetById" | "TryGetByIdLong" if read => {
            operand_as_u8(instruction.operands.get(2))
        }
        "PutById" | "PutByIdLong" if !read => operand_as_u8(instruction.operands.get(2)),
        _ => None,
    }
}

fn operand_as_u8(operand: Option<&DecodedOperand>) -> Option<u8> {
    match operand {
        Some(DecodedOperand::U8(value)) => Some(*value),
        Some(DecodedOperand::U16(value)) => (*value).try_into().ok(),
        Some(DecodedOperand::U32(value)) => (*value).try_into().ok(),
        _ => None,
    }
}

fn ensure_small_header_fits(header: &FunctionHeader) -> Option<()> {
    if header.offset >= (1 << 25)
        || header.param_count >= (1 << 7)
        || header.bytecode_size_in_bytes >= (1 << 15)
        || header.function_name >= (1 << 17)
        || header.info_offset >= (1 << 25)
        || header.frame_size >= (1 << 7)
        || header.environment_size >= (1 << 8)
    {
        None
    } else {
        Some(())
    }
}

fn build_string_tables(strings: &[String]) -> BuiltStringTable {
    let mut storage = Vec::new();
    let mut small_entries = Vec::with_capacity(strings.len());
    let mut overflow_entries = Vec::new();

    for string in strings {
        let is_utf16 = !string.is_ascii();
        let offset = storage.len() as u32;
        let encoded = if is_utf16 {
            encode_utf16le(string)
        } else {
            string.as_bytes().to_vec()
        };
        let length_units = if is_utf16 {
            string.encode_utf16().count() as u32
        } else {
            encoded.len() as u32
        };
        storage.extend_from_slice(&encoded);

        let (small_offset, small_length) =
            if offset <= SMALL_STRING_MAX_OFFSET && length_units <= SMALL_STRING_MAX_LENGTH {
                (offset, length_units)
            } else {
                let overflow_index = overflow_entries.len() as u32;
                overflow_entries.push(OverflowStringTableEntry {
                    offset,
                    length: length_units,
                });
                (overflow_index, 0xff)
            };

        let raw = ((small_length & 0xff) << 24)
            | ((small_offset & SMALL_STRING_MAX_OFFSET) << 1)
            | u32::from(is_utf16);
        small_entries.push(SmallStringTableEntry {
            raw,
            is_utf16,
            offset: small_offset,
            length: small_length,
            is_overflowed: small_length == 0xff,
        });
    }

    BuiltStringTable {
        small_entries,
        overflow_entries,
        storage,
    }
}

fn classify_string_kinds(
    module: &MinimalModule,
    string_pool: &[String],
) -> Result<Vec<StringKind>, HbcBuildError> {
    let mut kinds = vec![StringKind::String; string_pool.len()];

    for function in &module.functions {
        for instruction in &function.instructions {
            if instruction.name == "LoadConstString" {
                continue;
            }

            if instruction.name == "DeclareGlobalVar" || instruction.name.contains("ById") {
                if let Some(string_id) = instruction_string_id(instruction) {
                    let slot = kinds.get_mut(string_id as usize).ok_or_else(|| {
                        HbcBuildError::MissingString {
                            function: function.name.clone(),
                            string_id,
                        }
                    })?;
                    *slot = StringKind::Identifier;
                }
            }
        }
    }

    Ok(kinds)
}

fn instruction_string_id(instruction: &DecodedInstruction) -> Option<u32> {
    match instruction.operands.last() {
        Some(DecodedOperand::U8(value)) => Some(*value as u32),
        Some(DecodedOperand::U16(value)) => Some(*value as u32),
        Some(DecodedOperand::U32(value)) => Some(*value),
        _ => None,
    }
}

fn build_identifier_hashes(strings: &[String], kinds: &[StringKind]) -> Vec<u32> {
    strings
        .iter()
        .zip(kinds.iter())
        .filter(|(_, kind)| **kind == StringKind::Identifier)
        .map(|(string, _)| hash_string(string))
        .collect()
}

fn encode_string_kind_entries(kinds: &[StringKind]) -> Vec<StringKindEntry> {
    let mut entries: Vec<StringKindEntry> = Vec::new();
    for kind in kinds {
        match entries.last_mut() {
            Some(last) if last.kind == *kind => {
                last.count += 1;
                last.raw = encode_string_kind_raw(last.kind, last.count);
            }
            _ => entries.push(StringKindEntry {
                raw: encode_string_kind_raw(*kind, 1),
                kind: *kind,
                count: 1,
            }),
        }
    }
    entries
}

fn encode_string_kind_raw(kind: StringKind, count: u32) -> u32 {
    let kind_bit = match kind {
        StringKind::String => 0,
        StringKind::Identifier => 1 << 31,
    };
    kind_bit | (count & 0x7fff_ffff)
}

fn count_runs(kinds: &[StringKind]) -> usize {
    encode_string_kind_entries(kinds).len()
}

fn encode_utf16le(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn intern_string_with_kind(
    pool: &mut Vec<String>,
    kinds: &mut Vec<StringKind>,
    value: &str,
    kind: StringKind,
) -> u32 {
    if let Some(index) = pool.iter().position(|candidate| candidate == value) {
        index as u32
    } else {
        pool.push(value.to_owned());
        kinds.push(kind);
        (pool.len() - 1) as u32
    }
}

fn write_u32_array(values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn hash_string(value: &str) -> u32 {
    value.encode_utf16().fold(0u32, |hash, c| {
        let hash = hash.wrapping_add(c as u32);
        let hash = hash.wrapping_add(hash << 10);
        hash ^ (hash >> 6)
    })
}

fn compute_sha1(bytes: &[u8]) -> [u8; FOOTER_SIZE] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; FOOTER_SIZE];
    out.copy_from_slice(&digest[..FOOTER_SIZE]);
    out
}

fn empty_debug_info_section(version: u32) -> Vec<u8> {
    if version >= 91 {
        vec![0u8; 7 * 4]
    } else {
        vec![0u8; 4 * 4]
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    if value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

fn pad_to(bytes: &mut Vec<u8>, target_len: usize) {
    if bytes.len() < target_len {
        bytes.resize(target_len, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_raw_module, parse_hbc_container_with_spec};
    use mercury_spec_builtin::load_spec;

    #[test]
    fn builds_and_reparses_minimal_hbc96_module() {
        let spec = load_spec(96).expect("embedded hbc96 spec");
        let module = MinimalModule {
            version: 96,
            global_code_index: 0,
            strings: vec!["encode".into(), "decode".into(), "".into()],
            string_kinds: vec![StringKind::Identifier, StringKind::Identifier, StringKind::String],
            literal_value_buffer: vec![0xaa],
            object_key_buffer: vec![0xbb, 0xcc],
            object_shape_table: vec![
                ShapeTableEntry {
                    key_buffer_offset: 0xdd,
                    num_props: 0xee,
                },
                ShapeTableEntry {
                    key_buffer_offset: 0xff,
                    num_props: 1,
                },
            ],
            functions: vec![
                MinimalFunction {
                    name: "global".into(),
                    param_count: 1,
                    frame_size: 3,
                    environment_size: 0,
                    instructions: vec![
                        DecodedInstruction {
                            offset: 0,
                            opcode: 93,
                            name: "DeclareGlobalVar".into(),
                            operands: vec![DecodedOperand::U32(0)],
                            size: 5,
                        },
                        DecodedInstruction {
                            offset: 5,
                            opcode: 75,
                            name: "CreateEnvironment".into(),
                            operands: vec![DecodedOperand::U8(0)],
                            size: 2,
                        },
                        DecodedInstruction {
                            offset: 7,
                            opcode: 113,
                            name: "LoadConstUndefined".into(),
                            operands: vec![DecodedOperand::U8(0)],
                            size: 2,
                        },
                        DecodedInstruction {
                            offset: 9,
                            opcode: 86,
                            name: "Ret".into(),
                            operands: vec![DecodedOperand::U8(0)],
                            size: 2,
                        },
                    ],
                },
                MinimalFunction {
                    name: "encode".into(),
                    param_count: 2,
                    frame_size: 2,
                    environment_size: 0,
                    instructions: vec![
                        DecodedInstruction {
                            offset: 0,
                            opcode: 111,
                            name: "LoadConstString".into(),
                            operands: vec![DecodedOperand::U8(0), DecodedOperand::U16(2)],
                            size: 4,
                        },
                        DecodedInstruction {
                            offset: 4,
                            opcode: 86,
                            name: "Ret".into(),
                            operands: vec![DecodedOperand::U8(0)],
                            size: 2,
                        },
                    ],
                },
            ],
        };

        let bytes = build_minimal_module(&module, &spec.bytecode).expect("builds");
        let container =
            parse_hbc_container_with_spec(&bytes, &spec.container).expect("reparses");
        let raw = decode_raw_module(&container, &bytes, &spec.bytecode).expect("decodes");

        assert_eq!(container.header.version, 96);
        assert_eq!(container.header.function_count, 2);
        assert_eq!(container.header.string_count, 4);
        assert_eq!(container.literal_value_buffer, vec![0xaa]);
        assert_eq!(container.object_key_buffer, vec![0xbb, 0xcc]);
        assert_eq!(
            container.object_shape_table,
            vec![
                ShapeTableEntry {
                    key_buffer_offset: 0xdd,
                    num_props: 0xee,
                },
                ShapeTableEntry {
                    key_buffer_offset: 0xff,
                    num_props: 1,
                },
            ]
        );
        assert_eq!(
            container.header.debug_info_offset as usize + empty_debug_info_section(96).len() + 20,
            bytes.len()
        );
        assert_eq!(raw.functions.len(), 2);
        assert_eq!(raw.functions[0].instructions[0].name, "DeclareGlobalVar");
        assert_eq!(raw.functions[1].instructions[0].name, "LoadConstString");
    }
}

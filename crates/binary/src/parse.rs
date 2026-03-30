use crate::functions::{
    compute_function_bodies, parse_function_infos, parse_small_function_header,
    resolve_overflowed_function_headers, FunctionBody, FunctionHeader, FunctionInfo,
};
use crate::header::{parse_file_header, HbcVersionedFileHeader, FILE_HEADER_SIZE};
use crate::sections::{
    compute_section_boundaries, compute_section_boundaries_with_spec, HbcSectionBoundaries,
    SMALL_FUNCTION_HEADER_SIZE,
};
use crate::tables::{
    parse_overflow_string_table_entries, parse_pair_table_entries, parse_shape_table_entries,
    parse_small_string_table_entries, parse_string_kind_entries, parse_u32_array,
    OverflowStringTableEntry, PairTableEntry, ShapeTableEntry, SmallStringTableEntry,
    StringKindEntry,
};
use mercury_spec::ContainerSpec;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed Hermes container with typed top-level tables and function metadata.
pub struct HbcContainer {
    pub header: HbcVersionedFileHeader,
    pub function_headers: Vec<FunctionHeader>,
    pub function_infos: Vec<FunctionInfo>,
    pub section_boundaries: HbcSectionBoundaries,
    pub string_kind_entries: Vec<StringKindEntry>,
    pub identifier_hashes: Vec<u32>,
    pub small_string_table_entries: Vec<SmallStringTableEntry>,
    pub overflow_string_table_entries: Vec<OverflowStringTableEntry>,
    pub string_storage: Vec<u8>,
    pub literal_value_buffer: Vec<u8>,
    pub object_key_buffer: Vec<u8>,
    pub object_shape_table: Vec<ShapeTableEntry>,
    pub cjs_module_entries: Vec<PairTableEntry>,
    pub function_source_entries: Vec<PairTableEntry>,
    function_bodies: Vec<FunctionBody>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Error returned when parsing a Hermes bytecode container.
pub enum HbcParseError {
    #[error("input too short: expected at least {expected} bytes, got {actual}")]
    InputTooShort { expected: usize, actual: usize },
    #[error("invalid magic: expected 0x{expected:016x}, got 0x{actual:016x}")]
    InvalidMagic { expected: u64, actual: u64 },
    #[error("declared file length {declared} exceeds actual input length {actual}")]
    FileLengthOutOfRange { declared: usize, actual: usize },
    #[error("function header table exceeds input bounds")]
    FunctionHeaderTableOutOfRange,
    #[error("large function header exceeds input bounds")]
    LargeFunctionHeaderOutOfRange,
    #[error("computed section range exceeds input bounds")]
    SectionOutOfRange,
    #[error("spec references unsupported section {section}")]
    UnsupportedSectionInSpec { section: String },
    #[error("spec does not provide a usable entry size for {table}")]
    UnsupportedTableEntryLayout { table: String },
    #[error("function body range exceeds input bounds")]
    FunctionBodyOutOfRange,
    #[error("function info range exceeds input bounds")]
    FunctionInfoOutOfRange,
}

/// Parses a Hermes container using Mercury's built-in layout rules.
pub fn parse_hbc_container(bytes: &[u8]) -> Result<HbcContainer, HbcParseError> {
    parse_hbc_container_impl(bytes, None)
}

/// Parses a Hermes container using an extracted versioned [`ContainerSpec`].
pub fn parse_hbc_container_with_spec(
    bytes: &[u8],
    container_spec: &ContainerSpec,
) -> Result<HbcContainer, HbcParseError> {
    parse_hbc_container_impl(bytes, Some(container_spec))
}

fn parse_hbc_container_impl(
    bytes: &[u8],
    container_spec: Option<&ContainerSpec>,
) -> Result<HbcContainer, HbcParseError> {
    if bytes.len() < FILE_HEADER_SIZE {
        return Err(HbcParseError::InputTooShort {
            expected: FILE_HEADER_SIZE,
            actual: bytes.len(),
        });
    }

    let header = parse_file_header(bytes)?;
    let declared_file_length = header.file_length as usize;
    if declared_file_length > bytes.len() {
        return Err(HbcParseError::FileLengthOutOfRange {
            declared: declared_file_length,
            actual: bytes.len(),
        });
    }

    let function_headers_start = FILE_HEADER_SIZE;
    let function_headers_len = header.function_count as usize * SMALL_FUNCTION_HEADER_SIZE;
    let function_headers_end = function_headers_start + function_headers_len;
    if function_headers_end > bytes.len() {
        return Err(HbcParseError::FunctionHeaderTableOutOfRange);
    }

    let mut function_headers = Vec::with_capacity(header.function_count as usize);
    for index in 0..header.function_count as usize {
        let start = function_headers_start + (index * SMALL_FUNCTION_HEADER_SIZE);
        let end = start + SMALL_FUNCTION_HEADER_SIZE;
        function_headers.push(parse_small_function_header(&bytes[start..end]));
    }
    resolve_overflowed_function_headers(bytes, &mut function_headers)?;

    let section_boundaries = if let Some(spec) = container_spec {
        compute_section_boundaries_with_spec(&header, spec)?
    } else {
        compute_section_boundaries(&header)?
    };
    if section_boundaries.function_bodies_start > bytes.len() {
        return Err(HbcParseError::SectionOutOfRange);
    }

    let string_kind_entries = parse_string_kind_entries(bytes, section_boundaries.string_kinds.clone())?;
    let identifier_hashes = parse_u32_array(bytes, section_boundaries.identifier_hashes.clone())?;
    let small_string_table_entries =
        parse_small_string_table_entries(bytes, section_boundaries.small_string_table.clone())?;
    let overflow_string_table_entries = parse_overflow_string_table_entries(
        bytes,
        section_boundaries.overflow_string_table.clone(),
    )?;
    let string_storage = bytes[section_boundaries.string_storage.clone()].to_vec();
    let literal_value_buffer = bytes[section_boundaries.literal_value_buffer.clone()].to_vec();
    let object_key_buffer = bytes[section_boundaries.obj_key_buffer.clone()].to_vec();
    let object_shape_table =
        parse_shape_table_entries(bytes, section_boundaries.obj_shape_table.clone())?;
    let cjs_module_entries = parse_pair_table_entries(bytes, section_boundaries.cjs_module_table.clone())?;
    let function_source_entries =
        parse_pair_table_entries(bytes, section_boundaries.function_source_table.clone())?;
    let function_bodies = compute_function_bodies(&function_headers, bytes.len())?;
    let function_infos = parse_function_infos(&function_headers, bytes)?;

    Ok(HbcContainer {
        header,
        function_headers,
        function_infos,
        section_boundaries,
        string_kind_entries,
        identifier_hashes,
        small_string_table_entries,
        overflow_string_table_entries,
        string_storage,
        literal_value_buffer,
        object_key_buffer,
        object_shape_table,
        cjs_module_entries,
        function_source_entries,
        function_bodies,
    })
}

impl HbcContainer {
    /// Returns parsed metadata for one function body.
    pub fn function_body(&self, function_index: usize) -> Option<&FunctionBody> {
        self.function_bodies.get(function_index)
    }

    /// Returns the raw byte slice for one function body from the original file bytes.
    pub fn function_body_bytes<'a>(&self, bytes: &'a [u8], function_index: usize) -> Option<&'a [u8]> {
        let body = self.function_body(function_index)?;
        Some(&bytes[body.byte_range.clone()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_function_instructions, decode_raw_function, DecodedOperand};
    use crate::header::HERMES_MAGIC;
    use crate::tables::StringKind;
    use mercury_ir::RawOperand;
    use std::fs;
    use std::path::PathBuf;
    use mercury_spec::HermesSpec;

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates directory")
            .parent()
            .expect("workspace root")
            .parent()
            .expect("workspace parent")
            .join("hermes-dec/tests")
            .join(name);
        fs::read(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
    }

    fn workspace_fixture(name: &str) -> Option<Vec<u8>> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates directory")
            .parent()
            .expect("workspace root")
            .join("test")
            .join(name);
        if !path.exists() {
            return None;
        }
        Some(
            fs::read(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
        )
    }

    #[test]
    fn parses_sample_hbc_header_and_function_headers() {
        let bytes = fixture_bytes("sample.hbc");
        let spec = load_generated_spec("hbc94.json");
        let parsed =
            parse_hbc_container_with_spec(&bytes, &spec.container).expect("sample.hbc should parse");

        assert_eq!(parsed.header.magic, HERMES_MAGIC);
        assert_eq!(parsed.header.version, 94);
        assert_eq!(parsed.header.file_length, 2256);
        assert_eq!(parsed.header.function_count, 8);
        assert_eq!(parsed.header.string_kind_count, 2);
        assert_eq!(parsed.header.identifier_count, 17);
        assert_eq!(parsed.header.string_count, 34);
        assert_eq!(parsed.header.string_storage_size, 238);
        assert_eq!(parsed.header.reg_exp_count, 1);
        assert_eq!(parsed.header.reg_exp_storage_size, 66);
        assert_eq!(parsed.header.function_source_count, 2);
        assert_eq!(parsed.header.debug_info_offset, 1592);
        assert!(!parsed.header.options.static_builtins);
        assert!(!parsed.header.options.cjs_modules_statically_resolved);
        assert!(parsed.header.options.has_async);

        assert_eq!(parsed.section_boundaries.file_header, 0..128);
        assert_eq!(parsed.section_boundaries.function_headers, 128..256);
        assert_eq!(parsed.section_boundaries.string_kinds, 256..264);
        assert_eq!(parsed.section_boundaries.identifier_hashes, 264..332);
        assert_eq!(parsed.section_boundaries.small_string_table, 332..468);
        assert_eq!(parsed.section_boundaries.string_storage, 468..706);
        assert_eq!(parsed.section_boundaries.reg_exp_table, 708..716);
        assert_eq!(parsed.section_boundaries.reg_exp_storage, 716..782);
        assert_eq!(parsed.section_boundaries.function_source_table, 784..800);
        assert_eq!(parsed.section_boundaries.function_bodies_start, 800);

        assert_eq!(parsed.function_headers.len(), 8);
        assert_eq!(parsed.function_infos.len(), 8);
        assert_eq!(parsed.string_kind_entries.len(), 2);
        assert_eq!(parsed.string_kind_entries[0].kind, StringKind::String);
        assert_eq!(parsed.string_kind_entries[0].count, 17);
        assert_eq!(parsed.string_kind_entries[1].kind, StringKind::Identifier);
        assert_eq!(parsed.string_kind_entries[1].count, 17);
        assert_eq!(parsed.identifier_hashes.len(), 17);
        assert_eq!(parsed.small_string_table_entries.len(), 34);
        assert_eq!(parsed.overflow_string_table_entries.len(), 0);
        assert_eq!(parsed.string_storage.len(), 238);
        assert_eq!(parsed.cjs_module_entries.len(), 0);
        assert_eq!(
            parsed.function_source_entries,
            vec![
                PairTableEntry { first: 3, second: 0 },
                PairTableEntry { first: 5, second: 0 },
            ]
        );
        assert!(parsed.function_infos[0].debug_offsets.is_some());
        assert!(parsed.function_infos[0].large_header_range.is_none());
        assert_eq!(parsed.function_infos[0].exception_handlers.len(), 0);
        assert_eq!(parsed.function_body(0).unwrap().byte_range, 0x320..0x40b);

        let f0 = &parsed.function_headers[0];
        assert_eq!(f0.offset, 0x320);
        assert_eq!(f0.param_count, 1);
        assert_eq!(f0.bytecode_size_in_bytes, 235);
        assert_eq!(f0.flags.has_debug_info, true);

        let f1 = &parsed.function_headers[1];
        assert_eq!(f1.offset, 0x40b);
        assert_eq!(f1.param_count, 2);
        assert_eq!(f1.bytecode_size_in_bytes, 30);

        let f3 = &parsed.function_headers[3];
        assert_eq!(f3.offset, 0x432);
        assert_eq!(f3.param_count, 2);
        assert_eq!(f3.bytecode_size_in_bytes, 124);

        let f7 = &parsed.function_headers[7];
        assert_eq!(f7.offset, 0x5a0);
        assert_eq!(f7.param_count, 1);
        assert_eq!(f7.bytecode_size_in_bytes, 37);
    }

    #[test]
    fn decodes_opening_instructions_of_sample_global_function() {
        let bytes = fixture_bytes("sample.hbc");
        let spec = load_generated_spec("hbc94.json");
        let parsed =
            parse_hbc_container_with_spec(&bytes, &spec.container).expect("sample.hbc should parse");
        let body = parsed
            .function_body_bytes(&bytes, 0)
            .expect("global function body should exist");
        let decoded =
            decode_function_instructions(body, &spec.bytecode).expect("instructions should decode");

        assert!(decoded.len() >= 6);
        assert_eq!(decoded[0].offset, 0);
        assert_eq!(decoded[0].name, "DeclareGlobalVar");
        assert_eq!(decoded[0].operands, vec![DecodedOperand::U32(17)]);

        assert_eq!(decoded[1].offset, 5);
        assert_eq!(decoded[1].name, "DeclareGlobalVar");
        assert_eq!(decoded[1].operands, vec![DecodedOperand::U32(19)]);

        assert_eq!(decoded[2].offset, 10);
        assert_eq!(decoded[2].name, "DeclareGlobalVar");
        assert_eq!(decoded[2].operands, vec![DecodedOperand::U32(25)]);

        assert_eq!(decoded[3].offset, 15);
        assert_eq!(decoded[3].name, "CreateEnvironment");
        assert_eq!(decoded[3].operands, vec![DecodedOperand::U8(1)]);

        assert_eq!(decoded[4].offset, 17);
        assert_eq!(decoded[4].name, "CreateAsyncClosure");
        assert_eq!(
            decoded[4].operands,
            vec![
                DecodedOperand::U8(2),
                DecodedOperand::U8(1),
                DecodedOperand::U16(1),
            ]
        );

        assert_eq!(decoded[5].offset, 22);
        assert_eq!(decoded[5].name, "GetGlobalObject");
        assert_eq!(decoded[5].operands, vec![DecodedOperand::U8(0)]);
    }

    #[test]
    fn decodes_sample_global_function_into_raw_ir() {
        let bytes = fixture_bytes("sample.hbc");
        let spec = load_generated_spec("hbc94.json");
        let parsed =
            parse_hbc_container_with_spec(&bytes, &spec.container).expect("sample.hbc should parse");
        let raw = decode_raw_function(&parsed, &bytes, 0, &spec.bytecode)
            .expect("raw function should decode");

        assert_eq!(raw.function_index, 0);
        assert_eq!(raw.offset, 0x320);
        assert_eq!(raw.bytecode_size_in_bytes, 235);
        assert_eq!(raw.param_count, 1);
        assert_eq!(raw.frame_size, 16);
        assert_eq!(raw.highest_read_cache_index, 9);
        assert_eq!(raw.highest_write_cache_index, 5);
        assert!(raw.flags.has_debug_info);
        assert_eq!(raw.instructions[0].name, "DeclareGlobalVar");
        assert_eq!(raw.instructions[0].operands, vec![RawOperand::U32(17)]);
        assert_eq!(raw.instructions[3].name, "CreateEnvironment");
        assert_eq!(raw.instructions[3].operands, vec![RawOperand::U8(1)]);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut bytes = fixture_bytes("sample.hbc");
        bytes[0] = 0;
        let err = parse_hbc_container(&bytes).expect_err("magic check should fail");
        assert!(matches!(err, HbcParseError::InvalidMagic { .. }));
    }

    #[test]
    fn parses_large_amazon_fixture_header_and_function_table_when_present() {
        let Some(bytes) = workspace_fixture("amazon.hbc") else {
            return;
        };

        let spec = load_generated_spec("hbc96.json");
        let parsed = parse_hbc_container_with_spec(&bytes, &spec.container)
            .expect("amazon.hbc should parse as a container");
        assert_eq!(parsed.header.version, 96);
        assert_eq!(parsed.header.file_length as usize, bytes.len());
        assert!(parsed.header.function_count > 200_000);
        assert_eq!(parsed.function_headers.len(), parsed.header.function_count as usize);
        assert_eq!(parsed.function_infos.len(), parsed.header.function_count as usize);
        assert_eq!(parsed.cjs_module_entries.len(), parsed.header.cjs_module_count as usize);
        assert_eq!(
            parsed.function_source_entries.len(),
            parsed.header.function_source_count as usize
        );
        assert!(parsed.section_boundaries.function_bodies_start > parsed.section_boundaries.function_headers.end);
        assert!(parsed.function_headers[0].offset > parsed.section_boundaries.function_headers.end as u32);
        assert!(parsed.function_headers[0].bytecode_size_in_bytes > 0);
        assert!(parsed.function_headers[1].bytecode_size_in_bytes > 0);
        assert!(!parsed.function_headers[0].flags.overflowed);
        assert!(!parsed.function_headers[1].flags.overflowed);
        assert!(parsed.function_headers[0].overflowed_from_small_header);
        assert!(parsed.function_headers[1].overflowed_from_small_header);
        assert!(parsed.function_infos[0].large_header_range.is_some());
        assert!(parsed.function_infos[1].large_header_range.is_some());

        let body0 = parsed.function_body(0).expect("first function body should resolve");
        assert_eq!(body0.byte_range.start, parsed.function_headers[0].offset as usize);
        assert_eq!(
            body0.byte_range.len(),
            parsed.function_headers[0].bytecode_size_in_bytes as usize
        );
        assert!(body0.byte_range.end <= bytes.len());

        for (header, info) in parsed.function_headers.iter().zip(parsed.function_infos.iter()).take(32) {
            assert_eq!(header.flags.has_exception_handler, !info.exception_handlers.is_empty());
            assert_eq!(header.flags.has_debug_info, info.debug_offsets.is_some());
        }
    }

    fn load_generated_spec(name: &str) -> HermesSpec {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates directory")
            .parent()
            .expect("workspace root")
            .join("spec/generated")
            .join(name);
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        serde_json::from_str(&body)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
    }
}

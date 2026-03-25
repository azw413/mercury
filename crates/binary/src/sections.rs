use std::ops::Range;

use crate::header::{HbcVersionedFileHeader, FILE_HEADER_SIZE};
use crate::parse::HbcParseError;
use mercury_spec::{ContainerSpec, RawTableSpec};

pub const SMALL_FUNCTION_HEADER_SIZE: usize = 16;
const BYTECODE_ALIGNMENT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbcSectionBoundaries {
    pub file_header: Range<usize>,
    pub function_headers: Range<usize>,
    pub string_kinds: Range<usize>,
    pub identifier_hashes: Range<usize>,
    pub small_string_table: Range<usize>,
    pub overflow_string_table: Range<usize>,
    pub string_storage: Range<usize>,
    pub array_buffer: Range<usize>,
    pub obj_key_buffer: Range<usize>,
    pub obj_value_buffer: Range<usize>,
    pub big_int_table: Range<usize>,
    pub big_int_storage: Range<usize>,
    pub reg_exp_table: Range<usize>,
    pub reg_exp_storage: Range<usize>,
    pub cjs_module_table: Range<usize>,
    pub function_source_table: Range<usize>,
    pub function_bodies_start: usize,
}

pub(crate) fn compute_section_boundaries(
    header: &HbcVersionedFileHeader,
) -> Result<HbcSectionBoundaries, HbcParseError> {
    let mut offset = FILE_HEADER_SIZE;

    let function_headers = offset..offset + (header.function_count as usize * SMALL_FUNCTION_HEADER_SIZE);
    offset = align_up(function_headers.end, BYTECODE_ALIGNMENT);

    let string_kinds = offset..offset + (header.string_kind_count as usize * 4);
    offset = align_up(string_kinds.end, BYTECODE_ALIGNMENT);

    let identifier_hashes = offset..offset + (header.identifier_count as usize * 4);
    offset = align_up(identifier_hashes.end, BYTECODE_ALIGNMENT);

    let small_string_table = offset..offset + (header.string_count as usize * 4);
    offset = align_up(small_string_table.end, BYTECODE_ALIGNMENT);

    let overflow_string_table = offset..offset + (header.overflow_string_count as usize * 8);
    offset = align_up(overflow_string_table.end, BYTECODE_ALIGNMENT);

    let string_storage = offset..offset + header.string_storage_size as usize;
    offset = align_up(string_storage.end, BYTECODE_ALIGNMENT);

    let array_buffer = offset..offset + header.array_buffer_size as usize;
    offset = align_up(array_buffer.end, BYTECODE_ALIGNMENT);

    let obj_key_buffer = offset..offset + header.obj_key_buffer_size as usize;
    offset = align_up(obj_key_buffer.end, BYTECODE_ALIGNMENT);

    let obj_value_buffer = offset..offset + header.obj_value_buffer_size as usize;
    offset = align_up(obj_value_buffer.end, BYTECODE_ALIGNMENT);

    let big_int_table = offset..offset + (header.big_int_count as usize * 8);
    offset = align_up(big_int_table.end, BYTECODE_ALIGNMENT);

    let big_int_storage = offset..offset + header.big_int_storage_size as usize;
    offset = align_up(big_int_storage.end, BYTECODE_ALIGNMENT);

    let reg_exp_table = offset..offset + (header.reg_exp_count as usize * 8);
    offset = align_up(reg_exp_table.end, BYTECODE_ALIGNMENT);

    let reg_exp_storage = offset..offset + header.reg_exp_storage_size as usize;
    offset = align_up(reg_exp_storage.end, BYTECODE_ALIGNMENT);

    let cjs_module_table = offset..offset + (header.cjs_module_count as usize * 8);
    offset = align_up(cjs_module_table.end, BYTECODE_ALIGNMENT);

    let function_source_table = offset..offset + (header.function_source_count as usize * 8);
    offset = align_up(function_source_table.end, BYTECODE_ALIGNMENT);

    if offset > header.file_length as usize {
        return Err(HbcParseError::SectionOutOfRange);
    }

    Ok(HbcSectionBoundaries {
        file_header: 0..FILE_HEADER_SIZE,
        function_headers,
        string_kinds,
        identifier_hashes,
        small_string_table,
        overflow_string_table,
        string_storage,
        array_buffer,
        obj_key_buffer,
        obj_value_buffer,
        big_int_table,
        big_int_storage,
        reg_exp_table,
        reg_exp_storage,
        cjs_module_table,
        function_source_table,
        function_bodies_start: offset,
    })
}

pub(crate) fn compute_section_boundaries_with_spec(
    header: &HbcVersionedFileHeader,
    container_spec: &ContainerSpec,
) -> Result<HbcSectionBoundaries, HbcParseError> {
    let function_headers = FILE_HEADER_SIZE
        ..FILE_HEADER_SIZE + (header.function_count as usize * SMALL_FUNCTION_HEADER_SIZE);
    let mut boundaries = HbcSectionBoundaries {
        file_header: 0..FILE_HEADER_SIZE,
        function_headers: function_headers.clone(),
        string_kinds: 0..0,
        identifier_hashes: 0..0,
        small_string_table: 0..0,
        overflow_string_table: 0..0,
        string_storage: 0..0,
        array_buffer: 0..0,
        obj_key_buffer: 0..0,
        obj_value_buffer: 0..0,
        big_int_table: 0..0,
        big_int_storage: 0..0,
        reg_exp_table: 0..0,
        reg_exp_storage: 0..0,
        cjs_module_table: 0..0,
        function_source_table: 0..0,
        function_bodies_start: 0,
    };

    let mut offset = function_headers.end;
    for section in &container_spec.sections {
        if section.name == "function_bodies" {
            break;
        }
        if matches!(section.name.as_str(), "file_header" | "function_headers") {
            continue;
        }

        let alignment = section.alignment.unwrap_or(1) as usize;
        offset = align_up(offset, alignment);
        let size = resolve_section_size(header, container_spec, &section.name)?;
        let range = offset..offset + size;
        apply_section_range(&mut boundaries, &section.name, range)?;
        offset += size;
    }

    if offset > header.file_length as usize {
        return Err(HbcParseError::SectionOutOfRange);
    }

    boundaries.function_bodies_start = offset;
    Ok(boundaries)
}

fn resolve_section_size(
    header: &HbcVersionedFileHeader,
    container_spec: &ContainerSpec,
    section_name: &str,
) -> Result<usize, HbcParseError> {
    match section_name {
        "string_kinds" => Ok(header.string_kind_count as usize * 4),
        "identifier_hashes" => Ok(header.identifier_count as usize * 4),
        "small_string_table" => Ok(header.string_count as usize * 4),
        "overflow_string_table" => Ok(header.overflow_string_count as usize * 8),
        "string_storage" => Ok(header.string_storage_size as usize),
        "array_buffer" => Ok(header.array_buffer_size as usize),
        "object_key_buffer" => Ok(header.obj_key_buffer_size as usize),
        "object_value_buffer" => Ok(header.obj_value_buffer_size as usize),
        "bigint_table" => Ok(
            header.big_int_count as usize
                * table_entry_size("bigint_table", &container_spec.raw_module.bigint_table)?,
        ),
        "bigint_storage" => Ok(header.big_int_storage_size as usize),
        "regexp_table" => Ok(
            header.reg_exp_count as usize
                * table_entry_size("regexp_table", &container_spec.raw_module.regexp_table)?,
        ),
        "regexp_storage" => Ok(header.reg_exp_storage_size as usize),
        "cjs_module_table" => Ok(
            header.cjs_module_count as usize
                * table_entry_size("cjs_module_table", &container_spec.raw_module.cjs_module_table)?,
        ),
        "function_source_table" => Ok(
            header.function_source_count as usize
                * table_entry_size(
                    "function_source_table",
                    &container_spec.raw_module.function_source_table,
                )?,
        ),
        other => Err(HbcParseError::UnsupportedSectionInSpec {
            section: other.to_owned(),
        }),
    }
}

fn table_entry_size(table_name: &str, table_spec: &RawTableSpec) -> Result<usize, HbcParseError> {
    match table_spec.entry_type.as_str() {
        "BigIntTableEntry" | "RegExpTableEntry" => Ok(8),
        "uint32_t" => Ok(4),
        "pair<uint32_t, uint32_t>" => Ok(8),
        other if other.contains("pair<uint32_t, uint32_t>") => Ok(8),
        _ => Err(HbcParseError::UnsupportedTableEntryLayout {
            table: table_name.to_owned(),
        }),
    }
}

fn apply_section_range(
    boundaries: &mut HbcSectionBoundaries,
    section_name: &str,
    range: Range<usize>,
) -> Result<(), HbcParseError> {
    match section_name {
        "string_kinds" => boundaries.string_kinds = range,
        "identifier_hashes" => boundaries.identifier_hashes = range,
        "small_string_table" => boundaries.small_string_table = range,
        "overflow_string_table" => boundaries.overflow_string_table = range,
        "string_storage" => boundaries.string_storage = range,
        "array_buffer" => boundaries.array_buffer = range,
        "object_key_buffer" => boundaries.obj_key_buffer = range,
        "object_value_buffer" => boundaries.obj_value_buffer = range,
        "bigint_table" => boundaries.big_int_table = range,
        "bigint_storage" => boundaries.big_int_storage = range,
        "regexp_table" => boundaries.reg_exp_table = range,
        "regexp_storage" => boundaries.reg_exp_storage = range,
        "cjs_module_table" => boundaries.cjs_module_table = range,
        "function_source_table" => boundaries.function_source_table = range,
        other => {
            return Err(HbcParseError::UnsupportedSectionInSpec {
                section: other.to_owned(),
            });
        }
    }
    Ok(())
}

pub fn align_up(value: usize, alignment: usize) -> usize {
    if value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{BytecodeOptions, HbcVersionedFileHeader, HERMES_MAGIC};
    use mercury_spec::{ContainerSpec, RawBufferSpec, RawDebugInfoSpec, RawDebugOffsetsSpec, RawExceptionHandlerSpec, RawFooterSpec, RawFunctionBodySpec, RawFunctionHeaderSpec, RawFunctionInfoSpec, RawModuleSpec, RawStringTableSpec, RawSubsectionSpec, RawTableSpec, SectionSpec, StructSpec, BitfieldSpec};

    fn sample_header() -> HbcVersionedFileHeader {
        HbcVersionedFileHeader {
            magic: HERMES_MAGIC,
            version: 94,
            source_hash: [0; 20],
            file_length: 2256,
            global_code_index: 0,
            function_count: 8,
            string_kind_count: 2,
            identifier_count: 17,
            string_count: 34,
            overflow_string_count: 0,
            string_storage_size: 238,
            big_int_count: 0,
            big_int_storage_size: 0,
            reg_exp_count: 1,
            reg_exp_storage_size: 66,
            array_buffer_size: 0,
            obj_key_buffer_size: 0,
            obj_value_buffer_size: 0,
            segment_id: 0,
            cjs_module_count: 0,
            function_source_count: 2,
            debug_info_offset: 1592,
            options: BytecodeOptions {
                raw: 0b100,
                static_builtins: false,
                cjs_modules_statically_resolved: false,
                has_async: true,
            },
        }
    }

    fn minimal_container_spec() -> ContainerSpec {
        ContainerSpec {
            magic: String::new(),
            delta_magic: String::new(),
            bytecode_options: BitfieldSpec { name: String::new(), fields: vec![] },
            file_header: StructSpec { name: String::new(), fields: vec![] },
            function_header_flags: BitfieldSpec { name: String::new(), fields: vec![] },
            function_header: StructSpec { name: String::new(), fields: vec![] },
            raw_module: RawModuleSpec {
                function_header: RawFunctionHeaderSpec { small_header_fields: vec![], small_header_flags: String::new(), large_header_fields: vec![], overflow_strategy: String::new() },
                function_body: RawFunctionBodySpec { opcode_stream_alignment: None, jump_table_alignment: None, jump_tables_inlined_after_opcodes: false, optional_padding_control: None, notes: vec![] },
                function_info: RawFunctionInfoSpec { info_alignment: Some(4), large_header_may_be_present: true, subsections: vec![RawSubsectionSpec { name: String::new(), alignment: Some(4), storage: String::new(), notes: vec![] }], notes: vec![] },
                exception_handlers: RawExceptionHandlerSpec { header_name: String::new(), table_entry_type: String::new(), alignment: Some(4), notes: vec![] },
                debug_offsets: RawDebugOffsetsSpec { record_type: String::new(), alignment: Some(4), notes: vec![] },
                debug_info: RawDebugInfoSpec { header_name: String::new(), alignment: Some(4), subsections: vec![], strip_behavior: None, notes: vec![] },
                string_table: RawStringTableSpec { small_entry_type: String::new(), overflow_entry_type: String::new(), overflow_strategy: String::new(), notes: vec![] },
                array_buffer: RawBufferSpec { alignment: Some(4), storage: String::new(), notes: vec![] },
                object_key_buffer: RawBufferSpec { alignment: Some(4), storage: String::new(), notes: vec![] },
                object_value_buffer: RawBufferSpec { alignment: Some(4), storage: String::new(), notes: vec![] },
                bigint_table: RawTableSpec { alignment: Some(4), entry_type: "BigIntTableEntry".into(), storage: String::new(), notes: vec![] },
                regexp_table: RawTableSpec { alignment: Some(4), entry_type: "RegExpTableEntry".into(), storage: String::new(), notes: vec![] },
                cjs_module_table: RawTableSpec { alignment: Some(4), entry_type: "pair<uint32_t, uint32_t>".into(), storage: String::new(), notes: vec![] },
                function_source_table: RawTableSpec { alignment: Some(4), entry_type: "pair<uint32_t, uint32_t>".into(), storage: String::new(), notes: vec![] },
                footer: RawFooterSpec { type_name: String::new(), hash_description: String::new(), notes: vec![] },
            },
            sections: vec![
                SectionSpec { name: "file_header".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "function_headers".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "string_kinds".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "identifier_hashes".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "small_string_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "overflow_string_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "string_storage".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "array_buffer".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "object_key_buffer".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "object_value_buffer".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "bigint_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "bigint_storage".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "regexp_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "regexp_storage".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "cjs_module_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "function_source_table".into(), alignment: Some(4), notes: vec![] },
                SectionSpec { name: "function_bodies".into(), alignment: None, notes: vec![] },
            ],
            notes: vec![],
        }
    }

    #[test]
    fn computes_legacy_section_boundaries() {
        let header = sample_header();
        let boundaries = compute_section_boundaries(&header).expect("sections compute");
        assert_eq!(boundaries.function_headers, 128..256);
        assert_eq!(boundaries.string_kinds, 256..264);
        assert_eq!(boundaries.identifier_hashes, 264..332);
        assert_eq!(boundaries.small_string_table, 332..468);
        assert_eq!(boundaries.function_source_table, 784..800);
        assert_eq!(boundaries.function_bodies_start, 800);
    }

    #[test]
    fn computes_spec_driven_section_boundaries() {
        let header = sample_header();
        let boundaries =
            compute_section_boundaries_with_spec(&header, &minimal_container_spec()).expect("sections compute");
        assert_eq!(boundaries.function_headers, 128..256);
        assert_eq!(boundaries.string_kinds, 256..264);
        assert_eq!(boundaries.identifier_hashes, 264..332);
        assert_eq!(boundaries.small_string_table, 332..468);
        assert_eq!(boundaries.function_source_table, 784..800);
        assert_eq!(boundaries.function_bodies_start, 800);
    }

    #[test]
    fn align_up_roundtrips_expected_values() {
        assert_eq!(align_up(16, 4), 16);
        assert_eq!(align_up(17, 4), 20);
        assert_eq!(align_up(31, 8), 32);
    }
}

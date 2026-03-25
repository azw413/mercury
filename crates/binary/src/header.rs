use crate::parse::HbcParseError;

pub const HERMES_MAGIC: u64 = 0x1F19_03C1_03BC_1FC6;
pub const FILE_HEADER_SIZE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbcVersionedFileHeader {
    pub magic: u64,
    pub version: u32,
    pub source_hash: [u8; 20],
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub big_int_count: u32,
    pub big_int_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_value_buffer_size: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
    pub options: BytecodeOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeOptions {
    pub raw: u8,
    pub static_builtins: bool,
    pub cjs_modules_statically_resolved: bool,
    pub has_async: bool,
}

pub(crate) fn parse_file_header(bytes: &[u8]) -> Result<HbcVersionedFileHeader, HbcParseError> {
    let magic = read_u64(bytes, 0);
    if magic != HERMES_MAGIC {
        return Err(HbcParseError::InvalidMagic {
            expected: HERMES_MAGIC,
            actual: magic,
        });
    }

    let mut source_hash = [0u8; 20];
    source_hash.copy_from_slice(&bytes[12..32]);
    let options_raw = bytes[108];

    Ok(HbcVersionedFileHeader {
        magic,
        version: read_u32(bytes, 8),
        source_hash,
        file_length: read_u32(bytes, 32),
        global_code_index: read_u32(bytes, 36),
        function_count: read_u32(bytes, 40),
        string_kind_count: read_u32(bytes, 44),
        identifier_count: read_u32(bytes, 48),
        string_count: read_u32(bytes, 52),
        overflow_string_count: read_u32(bytes, 56),
        string_storage_size: read_u32(bytes, 60),
        big_int_count: read_u32(bytes, 64),
        big_int_storage_size: read_u32(bytes, 68),
        reg_exp_count: read_u32(bytes, 72),
        reg_exp_storage_size: read_u32(bytes, 76),
        array_buffer_size: read_u32(bytes, 80),
        obj_key_buffer_size: read_u32(bytes, 84),
        obj_value_buffer_size: read_u32(bytes, 88),
        segment_id: read_u32(bytes, 92),
        cjs_module_count: read_u32(bytes, 96),
        function_source_count: read_u32(bytes, 100),
        debug_info_offset: read_u32(bytes, 104),
        options: BytecodeOptions {
            raw: options_raw,
            static_builtins: (options_raw & 0b001) != 0,
            cjs_modules_statically_resolved: (options_raw & 0b010) != 0,
            has_async: (options_raw & 0b100) != 0,
        },
    })
}

pub fn write_file_header(header: &HbcVersionedFileHeader) -> [u8; FILE_HEADER_SIZE] {
    let mut bytes = [0u8; FILE_HEADER_SIZE];
    bytes[0..8].copy_from_slice(&header.magic.to_le_bytes());
    bytes[8..12].copy_from_slice(&header.version.to_le_bytes());
    bytes[12..32].copy_from_slice(&header.source_hash);
    bytes[32..36].copy_from_slice(&header.file_length.to_le_bytes());
    bytes[36..40].copy_from_slice(&header.global_code_index.to_le_bytes());
    bytes[40..44].copy_from_slice(&header.function_count.to_le_bytes());
    bytes[44..48].copy_from_slice(&header.string_kind_count.to_le_bytes());
    bytes[48..52].copy_from_slice(&header.identifier_count.to_le_bytes());
    bytes[52..56].copy_from_slice(&header.string_count.to_le_bytes());
    bytes[56..60].copy_from_slice(&header.overflow_string_count.to_le_bytes());
    bytes[60..64].copy_from_slice(&header.string_storage_size.to_le_bytes());
    bytes[64..68].copy_from_slice(&header.big_int_count.to_le_bytes());
    bytes[68..72].copy_from_slice(&header.big_int_storage_size.to_le_bytes());
    bytes[72..76].copy_from_slice(&header.reg_exp_count.to_le_bytes());
    bytes[76..80].copy_from_slice(&header.reg_exp_storage_size.to_le_bytes());
    bytes[80..84].copy_from_slice(&header.array_buffer_size.to_le_bytes());
    bytes[84..88].copy_from_slice(&header.obj_key_buffer_size.to_le_bytes());
    bytes[88..92].copy_from_slice(&header.obj_value_buffer_size.to_le_bytes());
    bytes[92..96].copy_from_slice(&header.segment_id.to_le_bytes());
    bytes[96..100].copy_from_slice(&header.cjs_module_count.to_le_bytes());
    bytes[100..104].copy_from_slice(&header.function_source_count.to_le_bytes());
    bytes[104..108].copy_from_slice(&header.debug_info_offset.to_le_bytes());
    bytes[108] = header.options.raw;
    bytes
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_file_header_bytes() {
        let header = HbcVersionedFileHeader {
            magic: HERMES_MAGIC,
            version: 96,
            source_hash: [0x5a; 20],
            file_length: 1234,
            global_code_index: 1,
            function_count: 8,
            string_kind_count: 2,
            identifier_count: 17,
            string_count: 34,
            overflow_string_count: 0,
            string_storage_size: 238,
            big_int_count: 1,
            big_int_storage_size: 16,
            reg_exp_count: 1,
            reg_exp_storage_size: 66,
            array_buffer_size: 20,
            obj_key_buffer_size: 30,
            obj_value_buffer_size: 40,
            segment_id: 7,
            cjs_module_count: 3,
            function_source_count: 2,
            debug_info_offset: 900,
            options: BytecodeOptions {
                raw: 0b101,
                static_builtins: true,
                cjs_modules_statically_resolved: false,
                has_async: true,
            },
        };

        let bytes = write_file_header(&header);
        let reparsed = parse_file_header(&bytes).expect("header parses");
        assert_eq!(reparsed, header);
        assert_eq!(write_file_header(&reparsed), bytes);
    }
}

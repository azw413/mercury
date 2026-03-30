use std::ops::Range;

use crate::parse::HbcParseError;

const SMALL_FUNCTION_HEADER_SIZE: usize = 16;
const LARGE_FUNCTION_HEADER_SIZE: usize = 32;
const INFO_ALIGNMENT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded Hermes function header, including fields that overflow out of the small header.
pub struct FunctionHeader {
    pub offset: u32,
    pub param_count: u32,
    pub bytecode_size_in_bytes: u32,
    pub function_name: u32,
    pub info_offset: u32,
    pub frame_size: u32,
    pub environment_size: u32,
    pub highest_read_cache_index: u8,
    pub highest_write_cache_index: u8,
    pub flags: FunctionHeaderFlags,
    pub overflowed_from_small_header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded bitflags attached to a Hermes function header.
pub struct FunctionHeaderFlags {
    pub raw: u8,
    pub prohibit_invoke: u8,
    pub strict_mode: bool,
    pub has_exception_handler: bool,
    pub has_debug_info: bool,
    pub overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Byte range and size information for a function body within a container.
pub struct FunctionBody {
    pub function_index: usize,
    pub byte_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed per-function info record and its optional nested tables.
pub struct FunctionInfo {
    pub function_index: usize,
    pub info_offset: Option<u32>,
    pub large_header_range: Option<Range<usize>>,
    pub exception_handlers: Vec<ExceptionHandlerEntry>,
    pub debug_offsets: Option<DebugOffsetsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// One entry in a Hermes exception-handler table.
pub struct ExceptionHandlerEntry {
    pub start: u32,
    pub end: u32,
    pub target: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Debug-offset record attached to a Hermes function.
pub struct DebugOffsetsEntry {
    pub source_locations: u32,
    pub scope_desc_data: u32,
    pub textified_callees: u32,
}

pub(crate) fn parse_small_function_header(bytes: &[u8]) -> FunctionHeader {
    let w1 = read_u32(bytes, 0);
    let w2 = read_u32(bytes, 4);
    let w3 = read_u32(bytes, 8);
    let environment_size = bytes[12] as u32;
    let highest_read_cache_index = bytes[13];
    let highest_write_cache_index = bytes[14];
    let raw_flags = bytes[15];

    FunctionHeader {
        offset: w1 & ((1 << 25) - 1),
        param_count: (w1 >> 25) & ((1 << 7) - 1),
        bytecode_size_in_bytes: w2 & ((1 << 15) - 1),
        function_name: (w2 >> 15) & ((1 << 17) - 1),
        info_offset: w3 & ((1 << 25) - 1),
        frame_size: (w3 >> 25) & ((1 << 7) - 1),
        environment_size,
        highest_read_cache_index,
        highest_write_cache_index,
        flags: decode_function_header_flags(raw_flags),
        overflowed_from_small_header: (raw_flags & 0b0010_0000) != 0,
    }
}

pub(crate) fn resolve_overflowed_function_headers(
    bytes: &[u8],
    function_headers: &mut [FunctionHeader],
) -> Result<(), HbcParseError> {
    for header in function_headers {
        if !header.flags.overflowed {
            continue;
        }

        let large_header_offset = ((header.info_offset as usize) << 16) | header.offset as usize;
        *header = parse_large_function_header(bytes, large_header_offset)?;
    }

    Ok(())
}

pub(crate) fn parse_large_function_header(
    bytes: &[u8],
    offset: usize,
) -> Result<FunctionHeader, HbcParseError> {
    let end = offset + LARGE_FUNCTION_HEADER_SIZE;
    if end > bytes.len() {
        return Err(HbcParseError::LargeFunctionHeaderOutOfRange);
    }

    let raw_flags = bytes[offset + 30];
    Ok(FunctionHeader {
        offset: read_u32(bytes, offset),
        param_count: read_u32(bytes, offset + 4),
        bytecode_size_in_bytes: read_u32(bytes, offset + 8),
        function_name: read_u32(bytes, offset + 12),
        info_offset: read_u32(bytes, offset + 16),
        frame_size: read_u32(bytes, offset + 20),
        environment_size: read_u32(bytes, offset + 24),
        highest_read_cache_index: bytes[offset + 28],
        highest_write_cache_index: bytes[offset + 29],
        flags: decode_function_header_flags(raw_flags),
        overflowed_from_small_header: true,
    })
}

pub(crate) fn compute_function_bodies(
    function_headers: &[FunctionHeader],
    input_len: usize,
) -> Result<Vec<FunctionBody>, HbcParseError> {
    let mut bodies = Vec::with_capacity(function_headers.len());
    for (index, header) in function_headers.iter().enumerate() {
        let start = header.offset as usize;
        let end = start + header.bytecode_size_in_bytes as usize;
        if end > input_len {
            return Err(HbcParseError::FunctionBodyOutOfRange);
        }
        bodies.push(FunctionBody {
            function_index: index,
            byte_range: start..end,
        });
    }
    Ok(bodies)
}

pub(crate) fn parse_function_infos(
    function_headers: &[FunctionHeader],
    bytes: &[u8],
) -> Result<Vec<FunctionInfo>, HbcParseError> {
    let mut infos = Vec::with_capacity(function_headers.len());
    for (function_index, header) in function_headers.iter().enumerate() {
        infos.push(parse_function_info(function_index, header, bytes)?);
    }
    Ok(infos)
}

pub(crate) fn parse_function_info(
    function_index: usize,
    header: &FunctionHeader,
    bytes: &[u8],
) -> Result<FunctionInfo, HbcParseError> {
    if header.info_offset == 0 && !header.flags.has_exception_handler && !header.flags.has_debug_info
    {
        return Ok(FunctionInfo {
            function_index,
            info_offset: None,
            large_header_range: None,
            exception_handlers: Vec::new(),
            debug_offsets: None,
        });
    }

    let mut cursor = header.info_offset as usize;
    if cursor > bytes.len() {
        return Err(HbcParseError::FunctionInfoOutOfRange);
    }

    let large_header_range = if header.overflowed_from_small_header {
        cursor = align_up(cursor, INFO_ALIGNMENT);
        let end = cursor + LARGE_FUNCTION_HEADER_SIZE;
        if end > bytes.len() {
            return Err(HbcParseError::FunctionInfoOutOfRange);
        }
        let range = cursor..end;
        cursor = end;
        Some(range)
    } else {
        None
    };

    let mut exception_handlers = Vec::new();
    if header.flags.has_exception_handler {
        cursor = align_up(cursor, INFO_ALIGNMENT);
        let count_end = cursor + 4;
        if count_end > bytes.len() {
            return Err(HbcParseError::FunctionInfoOutOfRange);
        }
        let count = read_u32(bytes, cursor) as usize;
        cursor = count_end;
        let table_end = cursor + (count * 12);
        if table_end > bytes.len() {
            return Err(HbcParseError::FunctionInfoOutOfRange);
        }
        for _ in 0..count {
            exception_handlers.push(ExceptionHandlerEntry {
                start: read_u32(bytes, cursor),
                end: read_u32(bytes, cursor + 4),
                target: read_u32(bytes, cursor + 8),
            });
            cursor += 12;
        }
    }

    let debug_offsets = if header.flags.has_debug_info {
        cursor = align_up(cursor, INFO_ALIGNMENT);
        let end = cursor + 12;
        if end > bytes.len() {
            return Err(HbcParseError::FunctionInfoOutOfRange);
        }
        Some(DebugOffsetsEntry {
            source_locations: read_u32(bytes, cursor),
            scope_desc_data: read_u32(bytes, cursor + 4),
            textified_callees: read_u32(bytes, cursor + 8),
        })
    } else {
        None
    };

    Ok(FunctionInfo {
        function_index,
        info_offset: Some(header.info_offset),
        large_header_range,
        exception_handlers,
        debug_offsets,
    })
}

/// Serializes a small Hermes function header.
pub fn write_small_function_header(header: &FunctionHeader) -> [u8; SMALL_FUNCTION_HEADER_SIZE] {
    let mut bytes = [0u8; SMALL_FUNCTION_HEADER_SIZE];
    let w1 = (header.offset & ((1 << 25) - 1)) | ((header.param_count & ((1 << 7) - 1)) << 25);
    let w2 = (header.bytecode_size_in_bytes & ((1 << 15) - 1))
        | ((header.function_name & ((1 << 17) - 1)) << 15);
    let w3 = (header.info_offset & ((1 << 25) - 1)) | ((header.frame_size & ((1 << 7) - 1)) << 25);
    bytes[0..4].copy_from_slice(&w1.to_le_bytes());
    bytes[4..8].copy_from_slice(&w2.to_le_bytes());
    bytes[8..12].copy_from_slice(&w3.to_le_bytes());
    bytes[12] = header.environment_size as u8;
    bytes[13] = header.highest_read_cache_index;
    bytes[14] = header.highest_write_cache_index;
    bytes[15] = encode_function_header_flags(&header.flags);
    bytes
}

/// Serializes a large Hermes function header.
pub fn write_large_function_header(header: &FunctionHeader) -> [u8; LARGE_FUNCTION_HEADER_SIZE] {
    let mut bytes = [0u8; LARGE_FUNCTION_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&header.offset.to_le_bytes());
    bytes[4..8].copy_from_slice(&header.param_count.to_le_bytes());
    bytes[8..12].copy_from_slice(&header.bytecode_size_in_bytes.to_le_bytes());
    bytes[12..16].copy_from_slice(&header.function_name.to_le_bytes());
    bytes[16..20].copy_from_slice(&header.info_offset.to_le_bytes());
    bytes[20..24].copy_from_slice(&header.frame_size.to_le_bytes());
    bytes[24..28].copy_from_slice(&header.environment_size.to_le_bytes());
    bytes[28] = header.highest_read_cache_index;
    bytes[29] = header.highest_write_cache_index;
    bytes[30] = encode_function_header_flags(&header.flags);
    bytes
}

/// Serializes an exception-handler table.
pub fn write_exception_handler_table(entries: &[ExceptionHandlerEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + entries.len() * 12);
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.start.to_le_bytes());
        bytes.extend_from_slice(&entry.end.to_le_bytes());
        bytes.extend_from_slice(&entry.target.to_le_bytes());
    }
    bytes
}

/// Serializes a debug-offset record.
pub fn write_debug_offsets(entry: &DebugOffsetsEntry) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&entry.source_locations.to_le_bytes());
    bytes[4..8].copy_from_slice(&entry.scope_desc_data.to_le_bytes());
    bytes[8..12].copy_from_slice(&entry.textified_callees.to_le_bytes());
    bytes
}

fn decode_function_header_flags(raw_flags: u8) -> FunctionHeaderFlags {
    FunctionHeaderFlags {
        raw: raw_flags,
        prohibit_invoke: raw_flags & 0b11,
        strict_mode: (raw_flags & 0b0000_0100) != 0,
        has_exception_handler: (raw_flags & 0b0000_1000) != 0,
        has_debug_info: (raw_flags & 0b0001_0000) != 0,
        overflowed: (raw_flags & 0b0010_0000) != 0,
    }
}

fn encode_function_header_flags(flags: &FunctionHeaderFlags) -> u8 {
    (flags.prohibit_invoke & 0b11)
        | ((flags.strict_mode as u8) << 2)
        | ((flags.has_exception_handler as u8) << 3)
        | ((flags.has_debug_info as u8) << 4)
        | ((flags.overflowed as u8) << 5)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

fn align_up(value: usize, alignment: usize) -> usize {
    if value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_small_function_header_bytes() {
        let header = FunctionHeader {
            offset: 0x12345,
            param_count: 5,
            bytecode_size_in_bytes: 0x3456,
            function_name: 0x1abc,
            info_offset: 0x23456,
            frame_size: 12,
            environment_size: 7,
            highest_read_cache_index: 9,
            highest_write_cache_index: 3,
            flags: FunctionHeaderFlags {
                raw: 22,
                prohibit_invoke: 2,
                strict_mode: true,
                has_exception_handler: false,
                has_debug_info: true,
                overflowed: false,
            },
            overflowed_from_small_header: false,
        };

        let bytes = write_small_function_header(&header);
        let reparsed = parse_small_function_header(&bytes);
        assert_eq!(reparsed, header);
        assert_eq!(write_small_function_header(&reparsed), bytes);
    }

    #[test]
    fn roundtrips_large_function_header_bytes() {
        let header = FunctionHeader {
            offset: 0x1234567,
            param_count: 0x44,
            bytecode_size_in_bytes: 0x654321,
            function_name: 0x112233,
            info_offset: 0x334455,
            frame_size: 0x55,
            environment_size: 0x66,
            highest_read_cache_index: 0x77,
            highest_write_cache_index: 0x88,
            flags: FunctionHeaderFlags {
                raw: 57,
                prohibit_invoke: 1,
                strict_mode: false,
                has_exception_handler: true,
                has_debug_info: true,
                overflowed: true,
            },
            overflowed_from_small_header: true,
        };

        let bytes = write_large_function_header(&header);
        let reparsed = parse_large_function_header(&bytes, 0).expect("large header parses");
        assert_eq!(reparsed, header);
        assert_eq!(write_large_function_header(&reparsed), bytes);
    }

    #[test]
    fn roundtrips_exception_handler_table_bytes() {
        let entries = vec![
            ExceptionHandlerEntry {
                start: 1,
                end: 10,
                target: 20,
            },
            ExceptionHandlerEntry {
                start: 30,
                end: 40,
                target: 50,
            },
        ];

        let bytes = write_exception_handler_table(&entries);
        let header = FunctionHeader {
            offset: 0,
            param_count: 0,
            bytecode_size_in_bytes: 0,
            function_name: 0,
            info_offset: 0,
            frame_size: 0,
            environment_size: 0,
            highest_read_cache_index: 0,
            highest_write_cache_index: 0,
            flags: FunctionHeaderFlags {
                raw: 0,
                prohibit_invoke: 0,
                strict_mode: false,
                has_exception_handler: true,
                has_debug_info: false,
                overflowed: false,
            },
            overflowed_from_small_header: false,
        };
        let info = parse_function_info(0, &header, &bytes).expect("function info parses");
        assert_eq!(info.exception_handlers, entries);
        assert_eq!(write_exception_handler_table(&info.exception_handlers), bytes);
    }

    #[test]
    fn roundtrips_debug_offsets_bytes() {
        let entry = DebugOffsetsEntry {
            source_locations: 11,
            scope_desc_data: 22,
            textified_callees: 33,
        };
        let bytes = write_debug_offsets(&entry);
        let header = FunctionHeader {
            offset: 0,
            param_count: 0,
            bytecode_size_in_bytes: 0,
            function_name: 0,
            info_offset: 0,
            frame_size: 0,
            environment_size: 0,
            highest_read_cache_index: 0,
            highest_write_cache_index: 0,
            flags: FunctionHeaderFlags {
                raw: 0,
                prohibit_invoke: 0,
                strict_mode: false,
                has_exception_handler: false,
                has_debug_info: true,
                overflowed: false,
            },
            overflowed_from_small_header: false,
        };
        let info = parse_function_info(0, &header, &bytes).expect("function info parses");
        assert_eq!(info.debug_offsets, Some(entry.clone()));
        assert_eq!(write_debug_offsets(&entry), bytes);
    }
}

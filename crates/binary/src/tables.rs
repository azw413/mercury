use std::ops::Range;

use crate::parse::HbcParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringKindEntry {
    pub raw: u32,
    pub kind: StringKind,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    String,
    Identifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallStringTableEntry {
    pub raw: u32,
    pub is_utf16: bool,
    pub offset: u32,
    pub length: u32,
    pub is_overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverflowStringTableEntry {
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairTableEntry {
    pub first: u32,
    pub second: u32,
}

pub(crate) fn parse_string_kind_entries(
    bytes: &[u8],
    range: Range<usize>,
) -> Result<Vec<StringKindEntry>, HbcParseError> {
    let raw_entries = parse_u32_array(bytes, range)?;
    Ok(raw_entries
        .into_iter()
        .map(|raw| StringKindEntry {
            raw,
            kind: if (raw >> 31) == 0 {
                StringKind::String
            } else {
                StringKind::Identifier
            },
            count: raw & 0x7fff_ffff,
        })
        .collect())
}

pub(crate) fn parse_small_string_table_entries(
    bytes: &[u8],
    range: Range<usize>,
) -> Result<Vec<SmallStringTableEntry>, HbcParseError> {
    let raw_entries = parse_u32_array(bytes, range)?;
    Ok(raw_entries
        .into_iter()
        .map(|raw| {
            let length = (raw >> 24) & 0xff;
            SmallStringTableEntry {
                raw,
                is_utf16: (raw & 0x1) != 0,
                offset: (raw >> 1) & 0x7f_ff_ff,
                length,
                is_overflowed: length == 0xff,
            }
        })
        .collect())
}

pub(crate) fn parse_overflow_string_table_entries(
    bytes: &[u8],
    range: Range<usize>,
) -> Result<Vec<OverflowStringTableEntry>, HbcParseError> {
    if range.end > bytes.len() {
        return Err(HbcParseError::SectionOutOfRange);
    }
    let mut entries = Vec::new();
    let mut offset = range.start;
    while offset < range.end {
        entries.push(OverflowStringTableEntry {
            offset: read_u32(bytes, offset),
            length: read_u32(bytes, offset + 4),
        });
        offset += 8;
    }
    Ok(entries)
}

pub(crate) fn parse_u32_array(bytes: &[u8], range: Range<usize>) -> Result<Vec<u32>, HbcParseError> {
    if range.end > bytes.len() {
        return Err(HbcParseError::SectionOutOfRange);
    }
    let mut values = Vec::new();
    let mut offset = range.start;
    while offset < range.end {
        values.push(read_u32(bytes, offset));
        offset += 4;
    }
    Ok(values)
}

pub(crate) fn parse_pair_table_entries(
    bytes: &[u8],
    range: Range<usize>,
) -> Result<Vec<PairTableEntry>, HbcParseError> {
    if range.end > bytes.len() {
        return Err(HbcParseError::SectionOutOfRange);
    }
    let mut entries = Vec::new();
    let mut offset = range.start;
    while offset < range.end {
        entries.push(PairTableEntry {
            first: read_u32(bytes, offset),
            second: read_u32(bytes, offset + 4),
        });
        offset += 8;
    }
    Ok(entries)
}

pub fn write_string_kind_entries(entries: &[StringKindEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(entries.len() * 4);
    for entry in entries {
        bytes.extend_from_slice(&entry.raw.to_le_bytes());
    }
    bytes
}

pub fn write_small_string_table_entries(entries: &[SmallStringTableEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(entries.len() * 4);
    for entry in entries {
        bytes.extend_from_slice(&entry.raw.to_le_bytes());
    }
    bytes
}

pub fn write_overflow_string_table_entries(entries: &[OverflowStringTableEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(entries.len() * 8);
    for entry in entries {
        bytes.extend_from_slice(&entry.offset.to_le_bytes());
        bytes.extend_from_slice(&entry.length.to_le_bytes());
    }
    bytes
}

pub fn write_pair_table_entries(entries: &[PairTableEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(entries.len() * 8);
    for entry in entries {
        bytes.extend_from_slice(&entry.first.to_le_bytes());
        bytes.extend_from_slice(&entry.second.to_le_bytes());
    }
    bytes
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_string_kind_entries_bytes() {
        let entries = vec![
            StringKindEntry {
                raw: 17,
                kind: StringKind::String,
                count: 17,
            },
            StringKindEntry {
                raw: 0x8000_0003,
                kind: StringKind::Identifier,
                count: 3,
            },
        ];
        let bytes = write_string_kind_entries(&entries);
        let reparsed = parse_string_kind_entries(&bytes, 0..bytes.len()).expect("parses");
        assert_eq!(reparsed, entries);
        assert_eq!(write_string_kind_entries(&reparsed), bytes);
    }

    #[test]
    fn roundtrips_small_string_table_entries_bytes() {
        let entries = vec![
            SmallStringTableEntry {
                raw: 0x0302_0001,
                is_utf16: true,
                offset: (0x0302_0001 >> 1) & 0x7f_ff_ff,
                length: (0x0302_0001 >> 24) & 0xff,
                is_overflowed: false,
            },
            SmallStringTableEntry {
                raw: 0xff00_0000,
                is_utf16: false,
                offset: 0,
                length: 0xff,
                is_overflowed: true,
            },
        ];
        let bytes = write_small_string_table_entries(&entries);
        let reparsed =
            parse_small_string_table_entries(&bytes, 0..bytes.len()).expect("parses");
        assert_eq!(reparsed, entries);
        assert_eq!(write_small_string_table_entries(&reparsed), bytes);
    }

    #[test]
    fn roundtrips_overflow_string_table_entries_bytes() {
        let entries = vec![
            OverflowStringTableEntry {
                offset: 123,
                length: 456,
            },
            OverflowStringTableEntry {
                offset: 789,
                length: 321,
            },
        ];
        let bytes = write_overflow_string_table_entries(&entries);
        let reparsed =
            parse_overflow_string_table_entries(&bytes, 0..bytes.len()).expect("parses");
        assert_eq!(reparsed, entries);
        assert_eq!(write_overflow_string_table_entries(&reparsed), bytes);
    }

    #[test]
    fn roundtrips_pair_table_entries_bytes() {
        let entries = vec![
            PairTableEntry { first: 3, second: 0 },
            PairTableEntry {
                first: 5,
                second: 99,
            },
        ];
        let bytes = write_pair_table_entries(&entries);
        let reparsed = parse_pair_table_entries(&bytes, 0..bytes.len()).expect("parses");
        assert_eq!(reparsed, entries);
        assert_eq!(write_pair_table_entries(&reparsed), bytes);
    }
}

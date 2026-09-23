//! Decoder for the HBC-96 serialized literal value buffer.

use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum LiteralValue {
    Null,
    Bool(bool),
    Number(f64),
    String(u32),
}

pub fn decode_buffer(buffer: &[u8], offset: u32, count: u32) -> Result<Vec<LiteralValue>, Error> {
    let mut cursor = usize::try_from(offset)
        .map_err(|_| Error::Bytecode("literal buffer offset does not fit this platform".into()))?;
    if cursor > buffer.len() {
        return Err(Error::Bytecode(format!(
            "literal buffer offset {offset} is outside the buffer"
        )));
    }
    let mut remaining = usize::try_from(count)
        .map_err(|_| Error::Bytecode("literal count does not fit this platform".into()))?;
    let mut values = Vec::with_capacity(remaining);

    while remaining != 0 {
        let tag = read::<1>(buffer, &mut cursor)?[0];
        let sequence_length = if tag & 0x80 != 0 {
            (usize::from(tag & 0x0f) << 8) | usize::from(read::<1>(buffer, &mut cursor)?[0])
        } else {
            usize::from(tag & 0x0f)
        };
        if sequence_length == 0 {
            return Err(Error::Bytecode(
                "literal buffer contains a zero-length sequence".into(),
            ));
        }
        // Hermes permits a user to consume a prefix of a serialized run.
        let take = sequence_length.min(remaining);
        remaining -= take;
        match tag & 0x70 {
            0x00 => values.extend((0..take).map(|_| LiteralValue::Null)),
            0x10 => values.extend((0..take).map(|_| LiteralValue::Bool(true))),
            0x20 => values.extend((0..take).map(|_| LiteralValue::Bool(false))),
            0x30 => {
                for _ in 0..take {
                    let bytes = read::<8>(buffer, &mut cursor)?;
                    values.push(LiteralValue::Number(f64::from_le_bytes(bytes)));
                }
            }
            0x40 => {
                for _ in 0..take {
                    let bytes = read::<4>(buffer, &mut cursor)?;
                    values.push(LiteralValue::String(u32::from_le_bytes(bytes)));
                }
            }
            0x50 => {
                for _ in 0..take {
                    let bytes = read::<2>(buffer, &mut cursor)?;
                    values.push(LiteralValue::String(u32::from(u16::from_le_bytes(bytes))));
                }
            }
            // HBC 96 uses tag 6 for one-byte string IDs. Later Hermes
            // versions repurposed it for undefined values.
            0x60 => {
                for _ in 0..take {
                    values.push(LiteralValue::String(u32::from(
                        read::<1>(buffer, &mut cursor)?[0],
                    )));
                }
            }
            0x70 => {
                for _ in 0..take {
                    let bytes = read::<4>(buffer, &mut cursor)?;
                    values.push(LiteralValue::Number(f64::from(i32::from_le_bytes(bytes))));
                }
            }
            _ => unreachable!("tag mask covers every three-bit literal tag"),
        }
    }
    Ok(values)
}

fn read<const N: usize>(buffer: &[u8], cursor: &mut usize) -> Result<[u8; N], Error> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| Error::Bytecode("literal buffer position overflow".into()))?;
    let bytes = buffer
        .get(*cursor..end)
        .ok_or_else(|| Error::Bytecode("truncated literal value buffer".into()))?;
    *cursor = end;
    Ok(bytes.try_into().expect("slice length was checked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mixed_runs_and_signed_integers() {
        let mut buffer = vec![0x02, 0x11, 0x21, 0x71];
        buffer.extend_from_slice(&(-7_i32).to_le_bytes());
        buffer.push(0x31);
        buffer.extend_from_slice(&3.5_f64.to_le_bytes());
        buffer.extend_from_slice(&[0x51, 9, 0, 0x41]);
        buffer.extend_from_slice(&70_000_u32.to_le_bytes());
        buffer.extend_from_slice(&[0x61, 7]);

        assert_eq!(
            decode_buffer(&buffer, 0, 9).unwrap(),
            vec![
                LiteralValue::Null,
                LiteralValue::Null,
                LiteralValue::Bool(true),
                LiteralValue::Bool(false),
                LiteralValue::Number(-7.0),
                LiteralValue::Number(3.5),
                LiteralValue::String(9),
                LiteralValue::String(70_000),
                LiteralValue::String(7),
            ]
        );
    }

    #[test]
    fn supports_extended_runs_and_rejects_malformed_buffers() {
        let buffer = [0x80, 0x10];
        assert_eq!(decode_buffer(&buffer, 0, 16).unwrap().len(), 16);

        let mut long_offset = vec![0; 70_000];
        long_offset.push(0x11);
        assert_eq!(
            decode_buffer(&long_offset, 70_000, 1).unwrap(),
            vec![LiteralValue::Bool(true)]
        );

        assert!(decode_buffer(&[0x00], 0, 1).is_err());
        assert!(decode_buffer(&[0x31, 0], 0, 1).is_err());
        assert!(decode_buffer(&[], 1, 1).is_err());
    }
}

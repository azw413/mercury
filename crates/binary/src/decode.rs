use crate::functions::FunctionHeader;
use crate::parse::HbcContainer;
use mercury_ir::{RawFunction, RawFunctionFlags, RawInstruction, RawModule, RawOperand, RawSectionBoundaries};
use mercury_spec::BytecodeSpec;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
/// One decoded instruction in a concrete Hermes bytecode version.
pub struct DecodedInstruction {
    pub offset: u32,
    pub opcode: u16,
    pub name: String,
    pub operands: Vec<DecodedOperand>,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq)]
/// Typed operand value produced by instruction decoding.
pub enum DecodedOperand {
    U8(u8),
    U16(u16),
    U32(u32),
    I8(i8),
    I32(i32),
    F64(f64),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Error returned when decoding Hermes function bodies.
pub enum HbcDecodeError {
    #[error("bytecode spec does not define opcode {opcode}")]
    UnknownOpcode { opcode: u8 },
    #[error("instruction operand kind {kind} is not supported yet")]
    UnsupportedOperandKind { kind: String },
    #[error("instruction extends past the end of the function body")]
    TruncatedInstruction,
}

/// Decodes a raw function-body byte slice into concrete instructions.
pub fn decode_function_instructions(
    body_bytes: &[u8],
    bytecode_spec: &BytecodeSpec,
) -> Result<Vec<DecodedInstruction>, HbcDecodeError> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < body_bytes.len() {
        let opcode = body_bytes[offset];
        let Some(spec) = bytecode_spec
            .instructions
            .iter()
            .find(|instruction| instruction.opcode == opcode as u16)
        else {
            return Err(HbcDecodeError::UnknownOpcode { opcode });
        };

        let mut cursor = offset + 1;
        let mut operands = Vec::with_capacity(spec.operands.len());
        for operand in &spec.operands {
            let decoded = decode_operand(body_bytes, &mut cursor, &operand.kind)?;
            operands.push(decoded);
        }

        instructions.push(DecodedInstruction {
            offset: offset as u32,
            opcode: opcode as u16,
            name: spec.name.clone(),
            operands,
            size: cursor - offset,
        });
        offset = cursor;
    }

    Ok(instructions)
}

/// Decodes one function from a parsed container into Mercury's raw IR.
pub fn decode_raw_function(
    container: &HbcContainer,
    bytes: &[u8],
    function_index: usize,
    bytecode_spec: &BytecodeSpec,
) -> Result<RawFunction, HbcDecodeError> {
    let body_bytes = container
        .function_body_bytes(bytes, function_index)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;
    let decoded = decode_function_instructions(body_bytes, bytecode_spec)?;
    let header = container
        .function_headers
        .get(function_index)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;

    Ok(raw_function_from_decoded(function_index, header, decoded))
}

/// Decodes every function in a parsed container into Mercury's raw IR.
pub fn decode_raw_module(
    container: &HbcContainer,
    bytes: &[u8],
    bytecode_spec: &BytecodeSpec,
) -> Result<RawModule, HbcDecodeError> {
    let mut functions = Vec::with_capacity(container.function_headers.len());
    for function_index in 0..container.function_headers.len() {
        functions.push(decode_raw_function(
            container,
            bytes,
            function_index,
            bytecode_spec,
        )?);
    }

    Ok(RawModule {
        version: container.header.version,
        function_count: container.header.function_count,
        sections: RawSectionBoundaries {
            function_bodies_start: container.section_boundaries.function_bodies_start,
        },
        functions,
    })
}

fn raw_function_from_decoded(
    function_index: usize,
    header: &FunctionHeader,
    decoded: Vec<DecodedInstruction>,
) -> RawFunction {
    RawFunction {
        function_index,
        offset: header.offset,
        bytecode_size_in_bytes: header.bytecode_size_in_bytes,
        param_count: header.param_count,
        frame_size: header.frame_size,
        environment_size: header.environment_size,
        highest_read_cache_index: header.highest_read_cache_index,
        highest_write_cache_index: header.highest_write_cache_index,
        flags: RawFunctionFlags {
            prohibit_invoke: header.flags.prohibit_invoke,
            strict_mode: header.flags.strict_mode,
            has_exception_handler: header.flags.has_exception_handler,
            has_debug_info: header.flags.has_debug_info,
            overflowed: header.flags.overflowed,
        },
        instructions: decoded
            .into_iter()
            .map(|instruction| RawInstruction {
                offset: instruction.offset,
                opcode: instruction.opcode,
                name: instruction.name,
                size: instruction.size,
                operands: instruction
                    .operands
                    .into_iter()
                    .map(|operand| match operand {
                        DecodedOperand::U8(value) => RawOperand::U8(value),
                        DecodedOperand::U16(value) => RawOperand::U16(value),
                        DecodedOperand::U32(value) => RawOperand::U32(value),
                        DecodedOperand::I8(value) => RawOperand::I8(value),
                        DecodedOperand::I32(value) => RawOperand::I32(value),
                        DecodedOperand::F64(value) => RawOperand::F64(value),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn decode_operand(
    body_bytes: &[u8],
    cursor: &mut usize,
    kind: &str,
) -> Result<DecodedOperand, HbcDecodeError> {
    match kind {
        "Reg8" | "UInt8" => {
            let value = *body_bytes.get(*cursor).ok_or(HbcDecodeError::TruncatedInstruction)?;
            *cursor += 1;
            Ok(DecodedOperand::U8(value))
        }
        "UInt16" => {
            let value = read_u16_checked(body_bytes, *cursor)?;
            *cursor += 2;
            Ok(DecodedOperand::U16(value))
        }
        "Reg32" | "UInt32" => {
            let value = read_u32_checked(body_bytes, *cursor)?;
            *cursor += 4;
            Ok(DecodedOperand::U32(value))
        }
        "Addr8" => {
            let value = *body_bytes.get(*cursor).ok_or(HbcDecodeError::TruncatedInstruction)? as i8;
            *cursor += 1;
            Ok(DecodedOperand::I8(value))
        }
        "Addr32" | "Imm32" => {
            let value = read_i32_checked(body_bytes, *cursor)?;
            *cursor += 4;
            Ok(DecodedOperand::I32(value))
        }
        "Double" => {
            let value = read_f64_checked(body_bytes, *cursor)?;
            *cursor += 8;
            Ok(DecodedOperand::F64(value))
        }
        _ => Err(HbcDecodeError::UnsupportedOperandKind {
            kind: kind.to_owned(),
        }),
    }
}

fn read_u16_checked(bytes: &[u8], offset: usize) -> Result<u16, HbcDecodeError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;
    let mut buf = [0u8; 2];
    buf.copy_from_slice(slice);
    Ok(u16::from_le_bytes(buf))
}

fn read_u32_checked(bytes: &[u8], offset: usize) -> Result<u32, HbcDecodeError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(u32::from_le_bytes(buf))
}

fn read_i32_checked(bytes: &[u8], offset: usize) -> Result<i32, HbcDecodeError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(i32::from_le_bytes(buf))
}

fn read_f64_checked(bytes: &[u8], offset: usize) -> Result<f64, HbcDecodeError> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or(HbcDecodeError::TruncatedInstruction)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(f64::from_le_bytes(buf))
}

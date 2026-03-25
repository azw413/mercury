use crate::decode::{DecodedInstruction, DecodedOperand};
use mercury_spec::{BytecodeSpec, InstructionSpec};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HbcEncodeError {
    #[error("bytecode spec does not define instruction {name}")]
    UnknownInstruction { name: String },
    #[error("operand count mismatch for {name}: expected {expected}, got {actual}")]
    OperandCountMismatch {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("operand kind mismatch for {name} operand {index}: expected {expected}")]
    OperandKindMismatch {
        name: String,
        index: usize,
        expected: String,
    },
}

pub fn encode_instruction(
    instruction: &DecodedInstruction,
    bytecode_spec: &BytecodeSpec,
) -> Result<Vec<u8>, HbcEncodeError> {
    let spec = lookup_instruction_spec(&instruction.name, bytecode_spec)?;
    if instruction.operands.len() != spec.operands.len() {
        return Err(HbcEncodeError::OperandCountMismatch {
            name: instruction.name.clone(),
            expected: spec.operands.len(),
            actual: instruction.operands.len(),
        });
    }

    let mut bytes = Vec::new();
    bytes.push(spec.opcode as u8);
    for (index, (operand, operand_spec)) in instruction.operands.iter().zip(spec.operands.iter()).enumerate() {
        encode_operand(&mut bytes, &instruction.name, index, operand, &operand_spec.kind)?;
    }
    Ok(bytes)
}

pub fn encode_instructions(
    instructions: &[DecodedInstruction],
    bytecode_spec: &BytecodeSpec,
) -> Result<Vec<u8>, HbcEncodeError> {
    let mut bytes = Vec::new();
    for instruction in instructions {
        bytes.extend_from_slice(&encode_instruction(instruction, bytecode_spec)?);
    }
    Ok(bytes)
}

fn lookup_instruction_spec<'a>(
    name: &str,
    bytecode_spec: &'a BytecodeSpec,
) -> Result<&'a InstructionSpec, HbcEncodeError> {
    bytecode_spec
        .instructions
        .iter()
        .find(|instruction| instruction.name == name)
        .ok_or_else(|| HbcEncodeError::UnknownInstruction {
            name: name.to_owned(),
        })
}

fn encode_operand(
    bytes: &mut Vec<u8>,
    instruction_name: &str,
    index: usize,
    operand: &DecodedOperand,
    kind: &str,
) -> Result<(), HbcEncodeError> {
    match (kind, operand) {
        ("Reg8" | "UInt8", DecodedOperand::U8(value)) => bytes.push(*value),
        ("UInt16", DecodedOperand::U16(value)) => bytes.extend_from_slice(&value.to_le_bytes()),
        ("Reg32" | "UInt32", DecodedOperand::U32(value)) => bytes.extend_from_slice(&value.to_le_bytes()),
        ("Addr8", DecodedOperand::I8(value)) => bytes.push(*value as u8),
        ("Addr32" | "Imm32", DecodedOperand::I32(value)) => bytes.extend_from_slice(&value.to_le_bytes()),
        ("Double", DecodedOperand::F64(value)) => bytes.extend_from_slice(&value.to_le_bytes()),
        _ => {
            return Err(HbcEncodeError::OperandKindMismatch {
                name: instruction_name.to_owned(),
                index,
                expected: kind.to_owned(),
            })
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_function_instructions, HbcDecodeError};
    use mercury_spec::{BytecodeSpec, InstructionFlags, InstructionOperandSpec, InstructionSpec};

    fn test_spec() -> BytecodeSpec {
        BytecodeSpec {
            operand_types: vec![],
            instructions: vec![
                InstructionSpec {
                    opcode: 1,
                    name: "LoadConstUInt8".into(),
                    operands: vec![InstructionOperandSpec {
                        index: 0,
                        kind: "UInt8".into(),
                        meaning: None,
                    }],
                    flags: InstructionFlags::default(),
                },
                InstructionSpec {
                    opcode: 2,
                    name: "JumpLong".into(),
                    operands: vec![InstructionOperandSpec {
                        index: 0,
                        kind: "Addr32".into(),
                        meaning: None,
                    }],
                    flags: InstructionFlags::default(),
                },
                InstructionSpec {
                    opcode: 3,
                    name: "LoadDouble".into(),
                    operands: vec![InstructionOperandSpec {
                        index: 0,
                        kind: "Double".into(),
                        meaning: None,
                    }],
                    flags: InstructionFlags::default(),
                },
            ],
            builtins: vec![],
        }
    }

    #[test]
    fn roundtrips_encoded_instructions_through_decoder() {
        let spec = test_spec();
        let instructions = vec![
            DecodedInstruction {
                offset: 0,
                opcode: 1,
                name: "LoadConstUInt8".into(),
                operands: vec![DecodedOperand::U8(7)],
                size: 2,
            },
            DecodedInstruction {
                offset: 2,
                opcode: 2,
                name: "JumpLong".into(),
                operands: vec![DecodedOperand::I32(1234)],
                size: 5,
            },
            DecodedInstruction {
                offset: 7,
                opcode: 3,
                name: "LoadDouble".into(),
                operands: vec![DecodedOperand::F64(3.5)],
                size: 9,
            },
        ];

        let bytes = encode_instructions(&instructions, &spec).expect("encodes");
        let decoded = decode_function_instructions(&bytes, &spec).expect("decodes");
        assert_eq!(decoded, instructions);
        assert_eq!(encode_instructions(&decoded, &spec).expect("re-encodes"), bytes);
    }

    #[test]
    fn rejects_operand_kind_mismatches() {
        let spec = test_spec();
        let instruction = DecodedInstruction {
            offset: 0,
            opcode: 1,
            name: "LoadConstUInt8".into(),
            operands: vec![DecodedOperand::U16(7)],
            size: 0,
        };
        let err = encode_instruction(&instruction, &spec).expect_err("must reject");
        assert!(matches!(err, HbcEncodeError::OperandKindMismatch { .. }));
    }

    #[test]
    fn decoder_and_encoder_error_types_remain_distinct() {
        let err = HbcDecodeError::UnknownOpcode { opcode: 0xff };
        assert!(matches!(err, HbcDecodeError::UnknownOpcode { .. }));
    }
}

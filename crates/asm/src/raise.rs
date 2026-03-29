use std::collections::{BTreeMap, HashMap};

use crate::ast::{
    SemanticAssemblyFunction, SemanticAssemblyInstruction, SemanticAssemblyModule,
    SemanticAssemblyStatement, SemanticOperand,
};
use mercury_binary::{DecodedInstruction, DecodedOperand};
use mercury_spec::BytecodeSpec;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct RaisedAssemblyModule {
    pub strings: Vec<String>,
    pub functions: Vec<RaisedAssemblyFunction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RaisedAssemblyFunction {
    pub name: String,
    pub params: u32,
    pub frame: u32,
    pub env: u32,
    pub instructions: Vec<DecodedInstruction>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RaiseError {
    #[error("unsupported mnemonic {mnemonic}")]
    UnsupportedMnemonic { mnemonic: String },
    #[error("invalid operand count for {mnemonic}: expected {expected}, got {actual}")]
    InvalidOperandCount {
        mnemonic: String,
        expected: usize,
        actual: usize,
    },
    #[error("unknown function reference @{name}")]
    UnknownFunction { name: String },
    #[error("unknown label {name}")]
    UnknownLabel { name: String },
    #[error("invalid operand for {mnemonic}")]
    InvalidOperand { mnemonic: String },
    #[error("instruction {name} is not available in the target bytecode spec")]
    MissingInstruction { name: String },
}

pub fn raise_module(
    module: &SemanticAssemblyModule,
    bytecode_spec: &BytecodeSpec,
) -> Result<RaisedAssemblyModule, RaiseError> {
    let function_ids = module
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.clone(), index as u32))
        .collect::<HashMap<_, _>>();
    // When semantic assembly includes a full `.strings` table, preserve it as
    // the canonical id ordering so raw literal/object buffers that embed string
    // ids stay valid across reassembly.
    let mut string_pool = module.strings.clone();
    let mut functions = Vec::with_capacity(module.functions.len());

    for function in &module.functions {
        functions.push(raise_function(
            function,
            &function_ids,
            &mut string_pool,
            bytecode_spec,
        )?);
    }

    Ok(RaisedAssemblyModule {
        strings: string_pool,
        functions,
    })
}

fn raise_function(
    function: &SemanticAssemblyFunction,
    function_ids: &HashMap<String, u32>,
    string_pool: &mut Vec<String>,
    bytecode_spec: &BytecodeSpec,
) -> Result<RaisedAssemblyFunction, RaiseError> {
    let labels = collect_label_offsets(function, bytecode_spec)?;
    let mut instructions = Vec::new();
    let mut offset = 0u32;

    for statement in &function.body {
        let SemanticAssemblyStatement::Instruction(instruction) = statement else {
            continue;
        };
        let decoded = raise_instruction(
            instruction,
            offset,
            &labels,
            function_ids,
            string_pool,
            bytecode_spec,
        )?;
        offset = offset.saturating_add(decoded.size as u32);
        instructions.push(decoded);
    }

    Ok(RaisedAssemblyFunction {
        name: function.name.clone(),
        params: function.params,
        frame: function.frame,
        env: function.env,
        instructions,
    })
}

fn collect_label_offsets(
    function: &SemanticAssemblyFunction,
    bytecode_spec: &BytecodeSpec,
) -> Result<BTreeMap<String, u32>, RaiseError> {
    let mut labels = BTreeMap::new();
    let mut offset = 0u32;

    for statement in &function.body {
        match statement {
            SemanticAssemblyStatement::Label(name) => {
                labels.insert(name.clone(), offset);
            }
            SemanticAssemblyStatement::Instruction(instruction) => {
                let size = estimate_instruction_size(instruction, bytecode_spec)?;
                offset = offset.saturating_add(size as u32);
            }
        }
    }

    Ok(labels)
}

fn estimate_instruction_size(
    instruction: &SemanticAssemblyInstruction,
    bytecode_spec: &BytecodeSpec,
) -> Result<usize, RaiseError> {
    let raw_name = raw_instruction_name(instruction)?;
    let spec = bytecode_spec
        .instructions
        .iter()
        .find(|candidate| candidate.name == raw_name)
        .ok_or_else(|| RaiseError::MissingInstruction { name: raw_name.clone() })?;

    let mut size = 1usize;
    for operand in &spec.operands {
        size += match operand.kind.as_str() {
            "Reg8" | "UInt8" | "Addr8" => 1,
            "UInt16" => 2,
            "Reg32" | "UInt32" | "Addr32" | "Imm32" => 4,
            "Double" => 8,
            _ => return Err(RaiseError::MissingInstruction { name: raw_name.clone() }),
        };
    }
    Ok(size)
}

fn raise_instruction(
    instruction: &SemanticAssemblyInstruction,
    offset: u32,
    labels: &BTreeMap<String, u32>,
    function_ids: &HashMap<String, u32>,
    string_pool: &mut Vec<String>,
    bytecode_spec: &BytecodeSpec,
) -> Result<DecodedInstruction, RaiseError> {
    let raw_name = raw_instruction_name(instruction)?;
    let spec = bytecode_spec
        .instructions
        .iter()
        .find(|candidate| candidate.name == raw_name)
        .ok_or_else(|| RaiseError::MissingInstruction { name: raw_name.clone() })?;

    let operands = raise_operands(
        instruction,
        &raw_name,
        offset,
        labels,
        function_ids,
        string_pool,
        spec.operands.iter().map(|operand| operand.kind.as_str()).collect(),
    )?;

    let size = estimate_instruction_size(instruction, bytecode_spec)?;
    Ok(DecodedInstruction {
        offset,
        opcode: spec.opcode,
        name: raw_name,
        operands,
        size,
    })
}

fn raise_operands(
    instruction: &SemanticAssemblyInstruction,
    raw_name: &str,
    offset: u32,
    labels: &BTreeMap<String, u32>,
    function_ids: &HashMap<String, u32>,
    string_pool: &mut Vec<String>,
    kinds: Vec<&str>,
) -> Result<Vec<DecodedOperand>, RaiseError> {
    let reordered = reorder_operands_for_raw_encoding(instruction);
    let operands = reordered.as_slice();

    let mut out = Vec::new();
    for (operand, kind) in operands.iter().zip(kinds.iter()) {
        out.push(match *kind {
            "Reg8" => match operand {
                SemanticOperand::Register(value) => DecodedOperand::U8(*value as u8),
                SemanticOperand::Integer(value) => DecodedOperand::U8(*value as u8),
                _ => return Err(RaiseError::InvalidOperand { mnemonic: raw_name.to_owned() }),
            },
            "Reg32" => match operand {
                SemanticOperand::Register(value) => DecodedOperand::U32(*value),
                SemanticOperand::Integer(value) => DecodedOperand::U32(*value as u32),
                _ => return Err(RaiseError::InvalidOperand { mnemonic: raw_name.to_owned() }),
            },
            "UInt8" => DecodedOperand::U8(resolve_u32(
                raw_name,
                operand,
                function_ids,
                string_pool,
            )? as u8),
            "UInt16" => DecodedOperand::U16(resolve_u32(
                raw_name,
                operand,
                function_ids,
                string_pool,
            )? as u16),
            "UInt32" => DecodedOperand::U32(resolve_u32(
                raw_name,
                operand,
                function_ids,
                string_pool,
            )?),
            "Addr8" => {
                let label = as_label(raw_name, operand)?;
                let target = labels
                    .get(label)
                    .ok_or_else(|| RaiseError::UnknownLabel { name: label.to_owned() })?;
                DecodedOperand::I8(target.wrapping_sub(offset) as i8)
            }
            "Addr32" => {
                let label = as_label(raw_name, operand)?;
                let target = labels
                    .get(label)
                    .ok_or_else(|| RaiseError::UnknownLabel { name: label.to_owned() })?;
                DecodedOperand::I32(target.wrapping_sub(offset) as i32)
            }
            "Imm32" => DecodedOperand::I32(as_i64(raw_name, operand)? as i32),
            "Double" => DecodedOperand::F64(as_f64(raw_name, operand)?),
            _ => return Err(RaiseError::InvalidOperand { mnemonic: raw_name.to_owned() }),
        });
    }

    Ok(out)
}

fn reorder_operands_for_raw_encoding(
    instruction: &SemanticAssemblyInstruction,
) -> Vec<SemanticOperand> {
    if instruction.mnemonic.starts_with("branch") && instruction.operands.len() >= 2 {
        let mut operands = instruction.operands.clone();
        if let Some(label_index) = operands
            .iter()
            .position(|operand| matches!(operand, SemanticOperand::Label(_)))
        {
            let label = operands.remove(label_index);
            let mut reordered = vec![label];
            reordered.extend(operands);
            return reordered;
        }
    }

    if instruction.mnemonic == "new_array" && instruction.operands.len() == 1 {
        return vec![
            instruction.operands[0].clone(),
            SemanticOperand::Integer(0),
        ];
    }

    instruction.operands.clone()
}

fn raw_instruction_name(instruction: &SemanticAssemblyInstruction) -> Result<String, RaiseError> {
    let name = match instruction.mnemonic.as_str() {
        "declare_global_var" => "DeclareGlobalVar",
        "create_environment" => "CreateEnvironment",
        "create_closure" => "CreateClosure",
        "create_this" => "CreateThis",
        "construct" => "Construct",
        "delete_property_by_id" => "DelById",
        "delete_property_by_value" => "DelByVal",
        "get_environment" => "GetEnvironment",
        "get_global_object" => "GetGlobalObject",
        "get_by_id" => "GetById",
        "put_by_id" => "PutById",
        "put_new_own_by_id" => "PutNewOwnById",
        "get_by_value" => "GetByVal",
        "put_by_value" => "PutByVal",
        "put_own_by_index" => "PutOwnByIndex",
        "load_immediate" => match instruction.operands.get(1) {
            Some(SemanticOperand::Bareword(value)) if value == "undefined" => "LoadConstUndefined",
            Some(SemanticOperand::Bareword(value)) if value == "null" => "LoadConstNull",
            Some(SemanticOperand::Bareword(value)) if value == "true" => "LoadConstTrue",
            Some(SemanticOperand::Bareword(value)) if value == "false" => "LoadConstFalse",
            Some(SemanticOperand::Integer(0)) => "LoadConstZero",
            Some(SemanticOperand::Integer(value)) if *value >= 0 && *value <= 255 => "LoadConstUInt8",
            Some(SemanticOperand::Integer(value)) if i32::try_from(*value).is_ok() => "LoadConstInt",
            Some(SemanticOperand::Integer(_)) => "LoadConstDouble",
            Some(SemanticOperand::Bareword(value)) if value.parse::<f64>().is_ok() => "LoadConstDouble",
            _ => return Err(RaiseError::UnsupportedMnemonic {
                mnemonic: instruction.mnemonic.clone(),
            }),
        },
        "load_from_environment" => "LoadFromEnvironment",
        "store_to_environment" => "StoreToEnvironment",
        "load_this_ns" => "LoadThisNS",
        "return" => "Ret",
        "load_param" => "LoadParam",
        "load_const_string" => "LoadConstString",
        "move" => "Mov",
        "new_array" => "NewArray",
        "new_object" => "NewObject",
        "new_object_with_buffer" => "NewObjectWithBuffer",
        "branch_true" => "JmpTrueLong",
        "branch_false" => "JmpFalseLong",
        "branch_undefined" => "JmpUndefinedLong",
        "branch" => "JmpLong",
        "branch_greater" => "JGreaterLong",
        "branch_greater_equal" => "JGreaterEqualLong",
        "branch_less" => "JLessLong",
        "branch_less_equal" => "JLessEqualLong",
        "branch_not_greater" => "JNotGreaterLong",
        "branch_not_greater_equal" => "JNotGreaterEqualLong",
        "branch_not_less" => "JNotLessLong",
        "branch_not_less_equal" => "JNotLessEqualLong",
        "branch_equal" => "JEqualLong",
        "branch_not_equal" => "JNotEqualLong",
        "branch_strict_equal" => "JStrictEqualLong",
        "branch_strict_not_equal" => "JStrictNotEqualLong",
        "get_by_id_short" => "GetByIdShort",
        "try_get_by_id" => "TryGetById",
        "call" => match instruction.operands.len() {
            3 => "Call1",
            4 => "Call2",
            5 => "Call3",
            6 => "Call4",
            _ => "Call",
        },
        "add" => "Add",
        "sub" => "Sub",
        "div" => "Div",
        "mul" => "Mul",
        "add_n" => "AddN",
        "bit_and" => "BitAnd",
        "bit_or" => "BitOr",
        "bit_not" => "BitNot",
        "dec" => "Dec",
        "mul_n" => "MulN",
        "div_n" => "DivN",
        "eq" => "Eq",
        "greater" => "Greater",
        "greater_eq" => "GreaterEq",
        "instance_of" => "InstanceOf",
        "less" => "Less",
        "less_eq" => "LessEq",
        "lshift" => "LShift",
        "mod" => "Mod",
        "negate" => "Negate",
        "neq" => "Neq",
        "reify_arguments" => "ReifyArguments",
        "rshift" => "RShift",
        "select_object" => "SelectObject",
        "strict_eq" => "StrictEq",
        "strict_neq" => "StrictNeq",
        "sub_n" => "SubN",
        "throw" => "Throw",
        "to_number" => "ToNumber",
        "to_numeric" => "ToNumeric",
        "type_of" => "TypeOf",
        "increment" => "Inc",
        other => {
            return Err(RaiseError::UnsupportedMnemonic {
                mnemonic: other.to_owned(),
            })
        }
    };

    Ok(name.to_owned())
}

fn resolve_u32(
    mnemonic: &str,
    operand: &SemanticOperand,
    function_ids: &HashMap<String, u32>,
    string_pool: &mut Vec<String>,
) -> Result<u32, RaiseError> {
    match operand {
        SemanticOperand::Integer(value) => Ok(*value as u32),
        SemanticOperand::FunctionRef(name) => function_ids
            .get(name)
            .copied()
            .ok_or_else(|| RaiseError::UnknownFunction { name: name.clone() }),
        SemanticOperand::String(value) => {
            let decoded = decode_string_literal(value).map_err(|_| RaiseError::InvalidOperand {
                mnemonic: mnemonic.to_owned(),
            })?;
            Ok(intern_string(string_pool, &decoded))
        }
        SemanticOperand::Bareword(value) if value == "undefined" => Ok(0),
        _ => Err(RaiseError::InvalidOperand {
            mnemonic: mnemonic.to_owned(),
        }),
    }
}

fn intern_string(pool: &mut Vec<String>, value: &str) -> u32 {
    if let Some(index) = pool.iter().position(|candidate| candidate == value) {
        index as u32
    } else {
        pool.push(value.to_owned());
        (pool.len() - 1) as u32
    }
}

fn decode_string_literal(value: &str) -> Result<String, serde_json::Error> {
    serde_json::from_str(value)
}

fn as_i64(mnemonic: &str, operand: &SemanticOperand) -> Result<i64, RaiseError> {
    match operand {
        SemanticOperand::Integer(value) => Ok(*value),
        _ => Err(RaiseError::InvalidOperand {
            mnemonic: mnemonic.to_owned(),
        }),
    }
}

fn as_f64(mnemonic: &str, operand: &SemanticOperand) -> Result<f64, RaiseError> {
    match operand {
        SemanticOperand::Integer(value) => Ok(*value as f64),
        SemanticOperand::Bareword(value) => value.parse().map_err(|_| RaiseError::InvalidOperand {
            mnemonic: mnemonic.to_owned(),
        }),
        _ => Err(RaiseError::InvalidOperand {
            mnemonic: mnemonic.to_owned(),
        }),
    }
}

fn as_label<'a>(mnemonic: &str, operand: &'a SemanticOperand) -> Result<&'a str, RaiseError> {
    match operand {
        SemanticOperand::Label(value) => Ok(value),
        _ => Err(RaiseError::InvalidOperand {
            mnemonic: mnemonic.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_semantic_assembly;
    use mercury_binary::{decode_function_instructions, encode_instructions};
    use mercury_spec_builtin::load_spec;

    #[test]
    fn raises_current_hex_style_subset_for_hbc96() {
        let asm = r#"
bytecode_version 96

.function @global params=1 frame=3 env=0
  declare_global_var "encode"
  create_environment r0
  create_closure r2, r0, @encode
  get_global_object r1
  put_by_id r1, r2, 1, "encode"
  load_immediate r0, undefined
  return r0
.end

.function @encode params=2 frame=25 env=0
  load_param r9, 1
  load_immediate r8, 0
  load_const_string r2, ""
  move r0, r2
  branch_false r10, L1
L1:
  return r0
.end
"#;

        let module = parse_semantic_assembly(asm).unwrap();
        let spec = load_spec(96).unwrap();
        let raised = raise_module(&module, &spec.bytecode).unwrap();

        assert_eq!(raised.functions.len(), 2);
        assert!(raised.strings.iter().any(|value| value == "encode"));
        assert!(raised.strings.iter().any(|value| value.is_empty()));

        let bytes = encode_instructions(&raised.functions[1].instructions, &spec.bytecode).unwrap();
        let decoded = decode_function_instructions(&bytes, &spec.bytecode).unwrap();
        assert_eq!(decoded.len(), raised.functions[1].instructions.len());
        assert_eq!(decoded[0].name, "LoadParam");
        assert_eq!(decoded[1].name, "LoadConstZero");
        assert_eq!(decoded[2].name, "LoadConstString");
        assert_eq!(decoded[3].name, "Mov");
        assert_eq!(decoded[4].name, "JmpFalseLong");
        assert_eq!(decoded[5].name, "Ret");
    }

    #[test]
    fn raises_additional_branch_aliases() {
        let asm = r#"
bytecode_version 96

.function @f params=1 frame=2 env=0
  branch_true r1, L1
  branch_less r2, r3, L2
L1:
  branch_strict_equal r4, r5, L2
L2:
  return r0
.end
"#;

        let module = parse_semantic_assembly(asm).unwrap();
        let spec = load_spec(96).unwrap();
        let raised = raise_module(&module, &spec.bytecode).unwrap();
        let instructions = &raised.functions[0].instructions;

        assert_eq!(instructions[0].name, "JmpTrueLong");
        assert_eq!(instructions[1].name, "JLessLong");
        assert_eq!(instructions[2].name, "JStrictEqualLong");
        assert_eq!(instructions[3].name, "Ret");
    }

    #[test]
    fn raises_current_hex_semantic_output_shape() {
        let asm = std::fs::read_to_string("/tmp/hex.semantic.current.txt").expect("hex semantic dump");
        let module = parse_semantic_assembly(&asm).unwrap();
        let spec = load_spec(96).unwrap();
        let raised = raise_module(&module, &spec.bytecode).unwrap();

        assert_eq!(raised.functions.len(), 3);

        let global = &raised.functions[0].instructions;
        assert_eq!(global[0].name, "DeclareGlobalVar");
        assert_eq!(global[2].name, "CreateEnvironment");
        assert_eq!(global[3].name, "CreateClosure");
        assert_eq!(global[5].name, "PutById");
        assert_eq!(global.last().unwrap().name, "Ret");

        let encode = &raised.functions[1].instructions;
        assert_eq!(encode[0].name, "LoadParam");
        assert_eq!(encode[1].name, "LoadConstZero");
        assert_eq!(encode[2].name, "Greater");
        assert!(encode.iter().any(|instruction| instruction.name == "Mov"));
        assert!(encode.iter().any(|instruction| instruction.name == "JGreaterLong"));
        assert_eq!(encode.last().unwrap().name, "Ret");

        let decode = &raised.functions[2].instructions;
        assert_eq!(decode[0].name, "GetGlobalObject");
        assert_eq!(decode[1].name, "GetByIdShort");
        assert!(decode.iter().any(|instruction| instruction.name == "JmpFalseLong"));
        assert_eq!(decode.last().unwrap().name, "Ret");
    }
}

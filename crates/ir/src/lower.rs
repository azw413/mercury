use crate::raw::{RawFunction, RawInstruction, RawModule, RawOperand};
use crate::semantic::{
    BinaryOpKind, BranchKind, ClosureKind, Immediate, PropertyAccessKind, Register,
    PropertyDefineKind, SemanticFunction, SemanticInstruction, SemanticModule, SemanticOp, Value,
    UnaryOpKind,
};
use mercury_spec::{BytecodeSpec, InstructionOperandSpec, OperandMeaning};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LoweringError {
    #[error("missing instruction spec for opcode {opcode} ({name})")]
    MissingInstructionSpec { opcode: u16, name: String },
    #[error("invalid operand shape for instruction {name}")]
    InvalidOperandShape { name: String },
}

pub fn lower_module(raw: &RawModule, bytecode_spec: &BytecodeSpec) -> Result<SemanticModule, LoweringError> {
    let mut functions = Vec::with_capacity(raw.functions.len());
    for function in &raw.functions {
        functions.push(lower_function(function, bytecode_spec)?);
    }

    Ok(SemanticModule {
        version: raw.version,
        functions,
    })
}

pub fn lower_function(
    raw: &RawFunction,
    bytecode_spec: &BytecodeSpec,
) -> Result<SemanticFunction, LoweringError> {
    let mut instructions = Vec::with_capacity(raw.instructions.len());
    for instruction in &raw.instructions {
        instructions.push(lower_instruction(instruction, bytecode_spec)?);
    }

    Ok(SemanticFunction {
        function_index: raw.function_index,
        name: None,
        param_count: raw.param_count,
        frame_size: raw.frame_size,
        environment_size: raw.environment_size,
        instructions,
    })
}

pub fn lower_instruction(
    raw: &RawInstruction,
    bytecode_spec: &BytecodeSpec,
) -> Result<SemanticInstruction, LoweringError> {
    let spec = bytecode_spec
        .instructions
        .iter()
        .find(|candidate| candidate.opcode == raw.opcode)
        .ok_or_else(|| LoweringError::MissingInstructionSpec {
            opcode: raw.opcode,
            name: raw.name.clone(),
        })?;

    let op = if let Some(branch) = lower_branch(raw, spec.operands.as_slice())? {
        branch
    } else if let Some(call_builtin) = lower_call_builtin(raw)? {
        call_builtin
    } else if let Some(create_environment) = lower_create_environment(raw)? {
        create_environment
    } else if let Some(get_environment) = lower_get_environment(raw)? {
        get_environment
    } else if let Some(global_object) = lower_get_global_object(raw)? {
        global_object
    } else if let Some(get_new_target) = lower_get_new_target(raw)? {
        get_new_target
    } else if let Some(load_param) = lower_load_param(raw, spec.operands.as_slice())? {
        load_param
    } else if let Some(load_from_environment) = lower_load_from_environment(raw, spec.operands.as_slice())? {
        load_from_environment
    } else if let Some(load_immediate) = lower_load_immediate(raw, spec.operands.as_slice())? {
        load_immediate
    } else if let Some(closure) = lower_closure(raw, spec.operands.as_slice())? {
        closure
    } else if let Some(construct) = lower_construct(raw, spec.operands.as_slice())? {
        construct
    } else if let Some(create_generator) = lower_create_generator(raw, spec.operands.as_slice())? {
        create_generator
    } else if let Some(create_reg_exp) = lower_create_reg_exp(raw)? {
        create_reg_exp
    } else if let Some(create_this) = lower_create_this(raw, spec.operands.as_slice())? {
        create_this
    } else if let Some(load_this_ns) = lower_load_this_ns(raw)? {
        load_this_ns
    } else if let Some(mov) = lower_move(raw, spec.operands.as_slice())? {
        mov
    } else if let Some(new_object) = lower_new_object(raw)? {
        new_object
    } else if let Some(new_array) = lower_new_array(raw)? {
        new_array
    } else if let Some(new_object_with_buffer) = lower_new_object_with_buffer(raw)? {
        new_object_with_buffer
    } else if let Some(new_array_with_buffer) = lower_new_array_with_buffer(raw)? {
        new_array_with_buffer
    } else if let Some(new_object_with_parent) = lower_new_object_with_parent(raw)? {
        new_object_with_parent
    } else if let Some(binary) = lower_binary(raw, spec.operands.as_slice())? {
        binary
    } else if let Some(unary) = lower_unary(raw, spec.operands.as_slice())? {
        unary
    } else if let Some(property_get) = lower_property_get(raw, spec.operands.as_slice())? {
        property_get
    } else if let Some(property_get_by_value) = lower_property_get_by_value(raw, spec.operands.as_slice())? {
        property_get_by_value
    } else if let Some(property_put) = lower_property_put(raw, spec.operands.as_slice())? {
        property_put
    } else if let Some(property_put_by_value) = lower_property_put_by_value(raw, spec.operands.as_slice())? {
        property_put_by_value
    } else if let Some(property_put_own_by_value) = lower_property_put_own_by_value(raw, spec.operands.as_slice())? {
        property_put_own_by_value
    } else if let Some(property_put_own_getter_setter_by_value) =
        lower_property_put_own_getter_setter_by_value(raw, spec.operands.as_slice())?
    {
        property_put_own_getter_setter_by_value
    } else if let Some(property_define) = lower_property_define(raw, spec.operands.as_slice())? {
        property_define
    } else if let Some(property_put_index) = lower_property_put_index(raw, spec.operands.as_slice())? {
        property_put_index
    } else if let Some(increment) = lower_increment(raw, spec.operands.as_slice())? {
        increment
    } else if let Some(catch) = lower_catch(raw)? {
        catch
    } else if let Some(complete_generator) = lower_complete_generator(raw)? {
        complete_generator
    } else if let Some(get_arguments_length) = lower_get_arguments_length(raw)? {
        get_arguments_length
    } else if let Some(get_arguments_prop_by_value) = lower_get_arguments_prop_by_value(raw, spec.operands.as_slice())? {
        get_arguments_prop_by_value
    } else if let Some(get_next_pname) = lower_get_next_pname(raw)? {
        get_next_pname
    } else if let Some(get_pname_list) = lower_get_pname_list(raw)? {
        get_pname_list
    } else if let Some(iterator_begin) = lower_iterator_begin(raw)? {
        iterator_begin
    } else if let Some(iterator_close) = lower_iterator_close(raw, spec.operands.as_slice())? {
        iterator_close
    } else if let Some(iterator_next) = lower_iterator_next(raw, spec.operands.as_slice())? {
        iterator_next
    } else if let Some(reify_arguments) = lower_reify_arguments(raw)? {
        reify_arguments
    } else if let Some(resume_generator) = lower_resume_generator(raw, spec.operands.as_slice())? {
        resume_generator
    } else if let Some(save_generator) = lower_save_generator(raw, spec.operands.as_slice())? {
        save_generator
    } else if let Some(start_generator) = lower_start_generator(raw)? {
        start_generator
    } else if let Some(store_to_environment) = lower_store_to_environment(raw, spec.operands.as_slice())? {
        store_to_environment
    } else if let Some(switch_imm) = lower_switch_imm(raw, spec.operands.as_slice())? {
        switch_imm
    } else if let Some(call) = lower_call(raw)? {
        call
    } else if let Some(string_load) = lower_string_load(raw, spec.operands.as_slice())? {
        string_load
    } else if let Some(global_decl) = lower_declare_global(raw, spec.operands.as_slice())? {
        global_decl
    } else if let Some(delete_property_by_id) = lower_delete_property_by_id(raw)? {
        delete_property_by_id
    } else if let Some(delete_property_by_value) = lower_delete_property_by_value(raw, spec.operands.as_slice())? {
        delete_property_by_value
    } else if let Some(direct_eval) = lower_direct_eval(raw, spec.operands.as_slice())? {
        direct_eval
    } else if let Some(throw) = lower_throw(raw, spec.operands.as_slice())? {
        throw
    } else if let Some(ret) = lower_return(raw, spec.operands.as_slice())? {
        ret
    } else {
        SemanticOp::Raw {
            mnemonic: raw.name.clone(),
            operands: spec
                .operands
                .iter()
                .zip(raw.operands.iter())
                .map(|(operand_spec, operand)| lower_typed_value(operand, operand_spec))
                .collect(),
        }
    };

    Ok(SemanticInstruction {
        offset: raw.offset,
        op,
    })
}

fn lower_branch(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "Jmp" | "JmpLong" => BranchKind::Jump,
        "JmpFalse" | "JmpFalseLong" => BranchKind::JumpFalse,
        "JmpTrue" | "JmpTrueLong" => BranchKind::JumpTrue,
        "JmpUndefined" | "JmpUndefinedLong" => BranchKind::JumpUndefined,
        "JGreater" | "JGreaterLong" | "JGreaterN" | "JGreaterNLong" => BranchKind::Greater,
        "JGreaterEqual" | "JGreaterEqualLong" | "JGreaterEqualN" | "JGreaterEqualNLong" => BranchKind::GreaterEqual,
        "JNotGreater" | "JNotGreaterLong" | "JNotGreaterN" | "JNotGreaterNLong" => BranchKind::NotGreater,
        "JNotGreaterEqual" | "JNotGreaterEqualLong" | "JNotGreaterEqualN" | "JNotGreaterEqualNLong" => BranchKind::NotGreaterEqual,
        "JLess" | "JLessLong" | "JLessN" | "JLessNLong" => BranchKind::Less,
        "JLessEqual" | "JLessEqualLong" | "JLessEqualN" | "JLessEqualNLong" => BranchKind::LessEqual,
        "JNotLess" | "JNotLessLong" | "JNotLessN" | "JNotLessNLong" => BranchKind::NotLess,
        "JNotLessEqual" | "JNotLessEqualLong" | "JNotLessEqualN" | "JNotLessEqualNLong" => BranchKind::NotLessEqual,
        "JEqual" | "JEqualLong" => BranchKind::Equal,
        "JNotEqual" | "JNotEqualLong" => BranchKind::NotEqual,
        "JStrictEqual" | "JStrictEqualLong" => BranchKind::StrictEqual,
        "JStrictNotEqual" | "JStrictNotEqualLong" => BranchKind::StrictNotEqual,
        _ => return Ok(None),
    };

    let Some(target) = operand_specs
        .iter()
        .zip(raw.operands.iter())
        .find_map(|(spec, operand)| match (spec.kind.as_str(), operand) {
            ("Addr8", RawOperand::I8(value)) => Some(raw.offset.wrapping_add_signed(*value as i32)),
            ("Addr32", RawOperand::I32(value)) => Some(raw.offset.wrapping_add_signed(*value)),
            _ => None,
        })
    else {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    };

    let args = operand_specs
        .iter()
        .zip(raw.operands.iter())
        .filter_map(|(spec, operand)| match spec.kind.as_str() {
            "Addr8" | "Addr32" => None,
            _ => Some(lower_typed_value(operand, spec)),
        })
        .collect();

    Ok(Some(SemanticOp::Branch { kind, target, args }))
}

fn lower_create_environment(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "CreateEnvironment" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::CreateEnvironment { dst }))
}

fn lower_call_builtin(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "CallBuiltin" || raw.operands.len() != 3 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let builtin = raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let argc = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::CallBuiltin { dst, builtin, argc }))
}

fn lower_get_global_object(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetGlobalObject" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::GetGlobalObject { dst }))
}

fn lower_get_new_target(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetNewTarget" || raw.operands.len() != 1 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::GetNewTarget { dst }))
}

fn lower_get_environment(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetEnvironment" {
        return Ok(None);
    }
    if raw.operands.len() != 2 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let level = raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::GetEnvironment { dst, level }))
}

fn lower_load_param(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "LoadParam" || raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let index = raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::LoadParam { dst, index }))
}

fn lower_load_immediate(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let value = match raw.name.as_str() {
        "LoadConstUndefined" => Immediate::Undefined,
        "LoadConstNull" => Immediate::Null,
        "LoadConstTrue" => Immediate::Bool(true),
        "LoadConstFalse" => Immediate::Bool(false),
        "LoadConstZero" => Immediate::U32(0),
        "LoadConstUInt8" => Immediate::U32(
            raw_u32(raw.operands.get(1).ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?)
            .ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?,
        ),
        "LoadConstInt" => Immediate::I32(
            raw_i32(raw.operands.get(1).ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?)
            .ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?,
        ),
        "LoadConstDouble" => Immediate::F64(
            raw_f64(raw.operands.get(1).ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?)
            .ok_or_else(|| LoweringError::InvalidOperandShape {
                name: raw.name.clone(),
            })?,
        ),
        _ => return Ok(None),
    };

    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    if raw.operands.len() != operand_specs.len() {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    Ok(Some(SemanticOp::LoadImmediate { dst, value }))
}

fn lower_load_from_environment(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "LoadFromEnvironment" | "LoadFromEnvironmentL")
        || raw.operands.len() != 3
        || operand_specs.len() != 3
    {
        return Ok(None);
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let environment = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let slot = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::LoadFromEnvironment {
        dst,
        environment,
        slot,
    }))
}

fn lower_closure(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "CreateClosure" | "CreateClosureLongIndex" => ClosureKind::Normal,
        "CreateGeneratorClosure" | "CreateGeneratorClosureLongIndex" => ClosureKind::Generator,
        "CreateAsyncClosure" | "CreateAsyncClosureLongIndex" => ClosureKind::Async,
        _ => return Ok(None),
    };

    if raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let environment = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let function = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::CreateClosure {
        kind,
        dst,
        environment,
        function,
    }))
}

fn lower_create_generator(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(
        raw.name.as_str(),
        "CreateGenerator" | "CreateGeneratorLongIndex"
    ) {
        return Ok(None);
    }
    if raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let environment = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let function = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::CreateGenerator {
        dst,
        environment,
        function,
    }))
}

fn lower_construct(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "Construct" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let callee = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let argument_count = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    Ok(Some(SemanticOp::Construct {
        dst,
        callee,
        argument_count,
    }))
}

fn lower_create_reg_exp(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "CreateRegExp" || raw.operands.len() != 4 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::CreateRegExp {
        dst,
        pattern_id: raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        flags_id: raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        regexp_id: raw_u32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_create_this(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "CreateThis" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let callee = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let new_target = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    Ok(Some(SemanticOp::CreateThis {
        dst,
        callee,
        new_target,
    }))
}

fn lower_load_this_ns(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "LoadThisNS" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::LoadThisNS { dst }))
}

fn lower_move(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "Mov" | "MovLong") || raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Ok(None);
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let src = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    Ok(Some(SemanticOp::Move { dst, src }))
}

fn lower_new_object(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "NewObject" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::NewObject { dst }))
}

fn lower_new_array(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "NewArray" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::NewArray { dst }))
}

fn lower_new_object_with_buffer(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "NewObjectWithBuffer" | "NewObjectWithBufferLong") {
        return Ok(None);
    }
    if raw.operands.len() != 5 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::NewObjectWithBuffer {
        dst,
        key_count: raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        value_count: raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        key_buffer_index: raw_u32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        shape_table_index: raw_u32(&raw.operands[4]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_new_array_with_buffer(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "NewArrayWithBuffer" | "NewArrayWithBufferLong") {
        return Ok(None);
    }
    if raw.operands.len() != 4 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::NewArrayWithBuffer {
        dst,
        min_size: raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        max_size: raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        buffer_index: raw_u32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_new_object_with_parent(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "NewObjectWithParent" || raw.operands.len() != 2 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let parent = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::NewObjectWithParent { dst, parent }))
}

fn lower_binary(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "Add" => BinaryOpKind::Add,
        "AddN" => BinaryOpKind::AddN,
        "BitAnd" => BinaryOpKind::BitAnd,
        "BitOr" => BinaryOpKind::BitOr,
        "BitXor" => BinaryOpKind::BitXor,
        "Sub" => BinaryOpKind::Sub,
        "SubN" => BinaryOpKind::SubN,
        "Mul" => BinaryOpKind::Mul,
        "MulN" => BinaryOpKind::MulN,
        "Div" => BinaryOpKind::Div,
        "DivN" => BinaryOpKind::DivN,
        "Eq" => BinaryOpKind::Eq,
        "IsIn" => BinaryOpKind::IsIn,
        "LShift" => BinaryOpKind::LShift,
        "Mod" => BinaryOpKind::Mod,
        "Neq" => BinaryOpKind::Neq,
        "RShift" => BinaryOpKind::RShift,
        "StrictEq" => BinaryOpKind::StrictEq,
        "StrictNeq" => BinaryOpKind::StrictNeq,
        "Greater" => BinaryOpKind::Greater,
        "GreaterEqual" => BinaryOpKind::GreaterEqual,
        "InstanceOf" => BinaryOpKind::InstanceOf,
        "Less" => BinaryOpKind::Less,
        "LessEqual" => BinaryOpKind::LessEqual,
        "SelectObject" => BinaryOpKind::SelectObject,
        "URShift" => BinaryOpKind::URShift,
        _ => return Ok(None),
    };

    if raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let lhs = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let rhs = lower_typed_value(&raw.operands[2], &operand_specs[2]);

    Ok(Some(SemanticOp::Binary { kind, dst, lhs, rhs }))
}

fn lower_unary(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "AddEmptyString" => UnaryOpKind::AddEmptyString,
        "BitNot" => UnaryOpKind::BitNot,
        "Dec" => UnaryOpKind::Dec,
        "Not" => UnaryOpKind::Not,
        "Negate" => UnaryOpKind::Negate,
        "ToInt32" => UnaryOpKind::ToInt32,
        "ToNumber" => UnaryOpKind::ToNumber,
        "ToNumeric" => UnaryOpKind::ToNumeric,
        "TypeOf" => UnaryOpKind::TypeOf,
        _ => return Ok(None),
    };

    if raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let operand = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    Ok(Some(SemanticOp::Unary { kind, dst, operand }))
}

fn lower_property_get(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "GetById" => PropertyAccessKind::ById,
        "GetByIdShort" => PropertyAccessKind::ByIdShort,
        "TryGetById" => PropertyAccessKind::TryById,
        "GetByIdLong" => PropertyAccessKind::ByIdLong,
        "TryGetByIdLong" => PropertyAccessKind::TryByIdLong,
        _ => return Ok(None),
    };

    if raw.operands.len() != 4 || operand_specs.len() != 4 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let object = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let cache_index = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = raw_u32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::PropertyGet {
        kind,
        dst,
        object,
        cache_index,
        key,
    }))
}

fn lower_property_get_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetByVal" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let object = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = lower_typed_value(&raw.operands[2], &operand_specs[2]);

    Ok(Some(SemanticOp::PropertyGetByValue { dst, object, key }))
}

fn lower_property_put(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "PutById" => PropertyAccessKind::ById,
        "PutByIdLong" => PropertyAccessKind::ByIdLong,
        _ => return Ok(None),
    };

    if raw.operands.len() != 4 || operand_specs.len() != 4 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let cache_index = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = raw_u32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::PropertyPut {
        kind,
        object,
        value,
        cache_index,
        key,
    }))
}

fn lower_property_put_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "PutByVal" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let value = lower_typed_value(&raw.operands[2], &operand_specs[2]);

    Ok(Some(SemanticOp::PropertyPutByValue { object, key, value }))
}

fn lower_property_put_own_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "PutOwnByVal" || raw.operands.len() != 4 || operand_specs.len() != 4 {
        return Ok(None);
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let value = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    let enumerable = lower_typed_value(&raw.operands[3], &operand_specs[3]);

    Ok(Some(SemanticOp::PropertyPutOwnByValue {
        object,
        key,
        value,
        enumerable,
    }))
}

fn lower_property_put_own_getter_setter_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "PutOwnGetterSetterByVal" || raw.operands.len() != 5 || operand_specs.len() != 5 {
        return Ok(None);
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let getter = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    let setter = lower_typed_value(&raw.operands[3], &operand_specs[3]);
    let enumerable = lower_typed_value(&raw.operands[4], &operand_specs[4]);

    Ok(Some(SemanticOp::PropertyPutOwnGetterSetterByValue {
        object,
        key,
        getter,
        setter,
        enumerable,
    }))
}

fn lower_property_define(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    let kind = match raw.name.as_str() {
        "PutNewOwnById" => PropertyDefineKind::NewOwnById,
        "PutNewOwnByIdShort" => PropertyDefineKind::NewOwnByIdShort,
        "PutNewOwnByIdLong" => PropertyDefineKind::NewOwnByIdLong,
        _ => return Ok(None),
    };

    if raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let key = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::PropertyDefine {
        kind,
        object,
        value,
        key,
    }))
}

fn lower_property_put_index(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "PutOwnByIndex" | "PutOwnByIndexL") {
        return Ok(None);
    }
    if raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let object = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let index = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::PropertyPutIndex {
        object,
        value,
        index,
    }))
}

fn lower_increment(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "Inc" || raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Ok(None);
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let src = lower_typed_value(&raw.operands[1], &operand_specs[1]);

    Ok(Some(SemanticOp::Increment { dst, src }))
}

fn lower_store_to_environment(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(
        raw.name.as_str(),
        "StoreToEnvironment" | "StoreNPToEnvironment" | "StoreToEnvironmentL"
    )
        || raw.operands.len() != 3
        || operand_specs.len() != 3
    {
        return Ok(None);
    }

    let environment = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    let slot = raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    Ok(Some(SemanticOp::StoreToEnvironment {
        environment,
        value,
        slot,
    }))
}

fn lower_switch_imm(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "SwitchImm" | "SwitchImmLong") || raw.operands.len() != 5 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::SwitchImm {
        input: operand_specs
            .first()
            .map(|spec| lower_typed_value(&raw.operands[0], spec))
            .unwrap_or_else(|| lower_value(&raw.operands[0])),
        table_offset: raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        default_offset: raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        min_case: raw_i32(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        max_case: raw_i32(&raw.operands[4]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_catch(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "Catch" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::Catch { dst }))
}

fn lower_get_arguments_length(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetArgumentsLength" || raw.operands.len() != 2 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let arguments = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::GetArgumentsLength { dst, arguments }))
}

fn lower_get_arguments_prop_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetArgumentsPropByVal" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let arguments = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let key = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    Ok(Some(SemanticOp::GetArgumentsPropByValue { dst, arguments, key }))
}

fn lower_get_pname_list(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetPNameList" || raw.operands.len() != 4 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::GetPNameList {
        dst: lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        iterator: lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        base: lower_register(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        index: lower_register(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_get_next_pname(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "GetNextPName" || raw.operands.len() != 5 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::GetNextPName {
        dst: lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        iterator: lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        base: lower_register(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        index: lower_register(&raw.operands[3]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        size: lower_register(&raw.operands[4]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_iterator_close(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "IteratorClose" || raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Ok(None);
    }
    let iterator = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    Ok(Some(SemanticOp::IteratorClose { iterator, value }))
}

fn lower_iterator_begin(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "IteratorBegin" || raw.operands.len() != 2 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let source = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::IteratorBegin { dst, source }))
}

fn lower_iterator_next(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "IteratorNext" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let iterator = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let source = lower_typed_value(&raw.operands[2], &operand_specs[2]);
    Ok(Some(SemanticOp::IteratorNext {
        dst,
        iterator,
        source,
    }))
}

fn lower_reify_arguments(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "ReifyArguments" {
        return Ok(None);
    }
    let dst = lower_register(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::ReifyArguments { dst }))
}

fn lower_resume_generator(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "ResumeGenerator" || raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Ok(None);
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let value = lower_typed_value(&raw.operands[1], &operand_specs[1]);
    Ok(Some(SemanticOp::ResumeGenerator { dst, value }))
}

fn lower_save_generator(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "SaveGenerator" || raw.operands.len() != 1 || operand_specs.len() != 1 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::SaveGenerator {
        value: lower_typed_value(&raw.operands[0], &operand_specs[0]),
    }))
}

fn lower_start_generator(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "StartGenerator" {
        return Ok(None);
    }
    Ok(Some(SemanticOp::StartGenerator))
}

fn lower_complete_generator(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "CompleteGenerator" {
        return Ok(None);
    }
    Ok(Some(SemanticOp::CompleteGenerator))
}

fn lower_call(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    let Some(suffix) = raw.name.strip_prefix("Call") else {
        return Ok(None);
    };

    if raw.operands.len() < 2 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }

    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let callee = lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;

    let (this_arg, args) = match suffix {
        "1" | "2" | "3" | "4" => {
            let this_arg = raw
                .operands
                .get(2)
                .and_then(lower_register)
                .ok_or_else(|| LoweringError::InvalidOperandShape {
                    name: raw.name.clone(),
                })?;
            let args = raw
                .operands
                .iter()
                .skip(3)
                .map(|operand| lower_register(operand).map(Value::Register).unwrap_or_else(|| lower_value(operand)))
                .collect();
            (Some(this_arg), args)
        }
        "" | "Long" => {
            let args = raw
                .operands
                .iter()
                .skip(2)
                .map(|operand| lower_register(operand).map(Value::Register).unwrap_or_else(|| lower_value(operand)))
                .collect();
            (None, args)
        }
        _ => {
            return Ok(None);
        }
    };

    Ok(Some(SemanticOp::Call {
        dst,
        callee,
        this_arg,
        args,
    }))
}

fn lower_string_load(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "LoadConstString" | "LoadConstStringLongIndex") {
        return Ok(None);
    }
    if raw.operands.len() != 2 || operand_specs.len() != 2 {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let dst = lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let string = raw_u32(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::LoadConstString { dst, string }))
}

fn lower_declare_global(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "DeclareGlobalVar" {
        return Ok(None);
    }
    let operand_spec = operand_specs.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    if operand_spec.meaning != Some(OperandMeaning::StringId) {
        return Err(LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        });
    }
    let name = raw_u32(raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?)
    .ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::DeclareGlobalVar { name }))
}

fn lower_return(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "Ret" {
        return Ok(None);
    }
    let operand = raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let operand_spec = operand_specs.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::Return {
        value: lower_typed_value(operand, operand_spec),
    }))
}

fn lower_throw(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "Throw" {
        return Ok(None);
    }
    let operand = raw.operands.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    let operand_spec = operand_specs.first().ok_or_else(|| LoweringError::InvalidOperandShape {
        name: raw.name.clone(),
    })?;
    Ok(Some(SemanticOp::Throw {
        value: lower_typed_value(operand, operand_spec),
    }))
}

fn lower_delete_property_by_id(raw: &RawInstruction) -> Result<Option<SemanticOp>, LoweringError> {
    if !matches!(raw.name.as_str(), "DelById" | "DelByIdLong") || raw.operands.len() != 3 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::DeletePropertyById {
        dst: lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        object: lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        key: raw_u32(&raw.operands[2]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
    }))
}

fn lower_delete_property_by_value(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "DelByVal" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::DeletePropertyByValue {
        dst: lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        object: lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        key: lower_typed_value(&raw.operands[2], &operand_specs[2]),
    }))
}

fn lower_direct_eval(
    raw: &RawInstruction,
    operand_specs: &[InstructionOperandSpec],
) -> Result<Option<SemanticOp>, LoweringError> {
    if raw.name != "DirectEval" || raw.operands.len() != 3 || operand_specs.len() != 3 {
        return Ok(None);
    }
    Ok(Some(SemanticOp::DirectEval {
        dst: lower_register(&raw.operands[0]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        callee: lower_register(&raw.operands[1]).ok_or_else(|| LoweringError::InvalidOperandShape {
            name: raw.name.clone(),
        })?,
        argument: lower_typed_value(&raw.operands[2], &operand_specs[2]),
    }))
}

fn lower_value(operand: &RawOperand) -> Value {
    match operand {
        RawOperand::U8(value) => Value::U32(*value as u32),
        RawOperand::U16(value) => Value::U32(*value as u32),
        RawOperand::U32(value) => Value::U32(*value),
        RawOperand::I8(value) => Value::I32(*value as i32),
        RawOperand::I32(value) => Value::I32(*value),
        RawOperand::F64(value) => Value::F64(*value),
    }
}

fn lower_typed_value(operand: &RawOperand, operand_spec: &InstructionOperandSpec) -> Value {
    match operand_spec.kind.as_str() {
        "Reg8" | "Reg32" => lower_register(operand)
            .map(Value::Register)
            .unwrap_or_else(|| lower_value(operand)),
        _ => lower_value(operand),
    }
}

fn lower_register(operand: &RawOperand) -> Option<Register> {
    match operand {
        RawOperand::U8(value) => Some(Register(*value as u32)),
        RawOperand::U32(value) => Some(Register(*value)),
        _ => None,
    }
}

fn raw_u32(operand: &RawOperand) -> Option<u32> {
    match operand {
        RawOperand::U8(value) => Some(*value as u32),
        RawOperand::U16(value) => Some(*value as u32),
        RawOperand::U32(value) => Some(*value),
        RawOperand::I8(value) => Some(*value as i32 as u32),
        RawOperand::I32(value) => Some(*value as u32),
        _ => None,
    }
}

fn raw_i32(operand: &RawOperand) -> Option<i32> {
    match operand {
        RawOperand::U8(value) => Some(*value as i32),
        RawOperand::U16(value) => Some(*value as i32),
        RawOperand::U32(value) => Some(*value as i32),
        RawOperand::I8(value) => Some(*value as i32),
        RawOperand::I32(value) => Some(*value),
        _ => None,
    }
}

fn raw_f64(operand: &RawOperand) -> Option<f64> {
    match operand {
        RawOperand::F64(value) => Some(*value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawFunctionFlags, RawSectionBoundaries};
    use mercury_spec::{BytecodeSpec, InstructionFlags, InstructionOperandSpec, InstructionSpec};

    fn operand(index: u8, kind: &str, meaning: Option<OperandMeaning>) -> InstructionOperandSpec {
        InstructionOperandSpec {
            index,
            kind: kind.to_string(),
            meaning,
        }
    }

    fn instruction(opcode: u16, name: &str, operands: Vec<InstructionOperandSpec>) -> InstructionSpec {
        InstructionSpec {
            opcode,
            name: name.to_string(),
            operands,
            flags: InstructionFlags::default(),
        }
    }

    fn bytecode_spec(instructions: Vec<InstructionSpec>) -> BytecodeSpec {
        BytecodeSpec {
            operand_types: Vec::new(),
            instructions,
            builtins: Vec::new(),
        }
    }

    #[test]
    fn lowers_branch_variants_to_semantic_branch() {
        let spec = bytecode_spec(vec![instruction(
            1,
            "JmpTrueLong",
            vec![operand(0, "Reg8", None), operand(1, "Addr32", None)],
        )]);
        let raw = RawInstruction {
            offset: 24,
            opcode: 1,
            name: "JmpTrueLong".to_string(),
            size: 6,
            operands: vec![RawOperand::U8(7), RawOperand::I32(16)],
        };

        let lowered = lower_instruction(&raw, &spec).unwrap();

        assert_eq!(
            lowered,
            SemanticInstruction {
                offset: 24,
                op: SemanticOp::Branch {
                    kind: BranchKind::JumpTrue,
                    target: 40,
                    args: vec![Value::Register(Register(7))],
                },
            }
        );
    }

    #[test]
    fn lowers_call_family_to_single_semantic_call_form() {
        let spec = bytecode_spec(vec![instruction(
            2,
            "Call3",
            vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "Reg8", None),
                operand(3, "Reg8", None),
                operand(4, "Reg8", None),
            ],
        )]);
        let raw = RawInstruction {
            offset: 8,
            opcode: 2,
            name: "Call3".to_string(),
            size: 6,
            operands: vec![
                RawOperand::U8(0),
                RawOperand::U8(1),
                RawOperand::U8(2),
                RawOperand::U8(3),
                RawOperand::U8(4),
            ],
        };

        let lowered = lower_instruction(&raw, &spec).unwrap();

        assert_eq!(
            lowered,
            SemanticInstruction {
                offset: 8,
                op: SemanticOp::Call {
                    dst: Register(0),
                    callee: Register(1),
                    this_arg: Some(Register(2)),
                    args: vec![Value::Register(Register(3)), Value::Register(Register(4))],
                },
            }
        );
    }

    #[test]
    fn lowers_string_and_closure_variants_to_semantic_forms() {
        let spec = bytecode_spec(vec![
            instruction(
                3,
                "LoadConstStringLongIndex",
                vec![
                    operand(0, "Reg8", None),
                    operand(1, "UInt32", Some(OperandMeaning::StringId)),
                ],
            ),
            instruction(
                4,
                "CreateGeneratorClosureLongIndex",
                vec![
                    operand(0, "Reg8", None),
                    operand(1, "Reg8", None),
                    operand(2, "UInt32", Some(OperandMeaning::FunctionId)),
                ],
            ),
        ]);
        let string_raw = RawInstruction {
            offset: 0,
            opcode: 3,
            name: "LoadConstStringLongIndex".to_string(),
            size: 6,
            operands: vec![RawOperand::U8(5), RawOperand::U32(99)],
        };
        let closure_raw = RawInstruction {
            offset: 6,
            opcode: 4,
            name: "CreateGeneratorClosureLongIndex".to_string(),
            size: 7,
            operands: vec![RawOperand::U8(9), RawOperand::U8(2), RawOperand::U32(11)],
        };

        let lowered_string = lower_instruction(&string_raw, &spec).unwrap();
        let lowered_closure = lower_instruction(&closure_raw, &spec).unwrap();

        assert_eq!(
            lowered_string,
            SemanticInstruction {
                offset: 0,
                op: SemanticOp::LoadConstString {
                    dst: Register(5),
                    string: 99,
                },
            }
        );
        assert_eq!(
            lowered_closure,
            SemanticInstruction {
                offset: 6,
                op: SemanticOp::CreateClosure {
                    kind: ClosureKind::Generator,
                    dst: Register(9),
                    environment: Register(2),
                    function: 11,
                },
            }
        );
    }

    #[test]
    fn lowers_raw_module_functions() {
        let spec = bytecode_spec(vec![
            instruction(
                5,
                "DeclareGlobalVar",
                vec![operand(0, "UInt16", Some(OperandMeaning::StringId))],
            ),
            instruction(6, "Ret", vec![operand(0, "Reg8", None)]),
        ]);
        let raw = RawModule {
            version: 96,
            function_count: 1,
            sections: RawSectionBoundaries {
                function_bodies_start: 64,
            },
            functions: vec![RawFunction {
                function_index: 0,
                offset: 100,
                bytecode_size_in_bytes: 4,
                param_count: 2,
                frame_size: 3,
                environment_size: 1,
                highest_read_cache_index: 0,
                highest_write_cache_index: 0,
                flags: RawFunctionFlags {
                    prohibit_invoke: 0,
                    strict_mode: false,
                    has_exception_handler: false,
                    has_debug_info: false,
                    overflowed: false,
                },
                instructions: vec![
                    RawInstruction {
                        offset: 100,
                        opcode: 5,
                        name: "DeclareGlobalVar".to_string(),
                        size: 3,
                        operands: vec![RawOperand::U16(17)],
                    },
                    RawInstruction {
                        offset: 103,
                        opcode: 6,
                        name: "Ret".to_string(),
                        size: 2,
                        operands: vec![RawOperand::U8(0)],
                    },
                ],
            }],
        };

        let lowered = lower_module(&raw, &spec).unwrap();

        assert_eq!(lowered.version, 96);
        assert_eq!(lowered.functions.len(), 1);
        assert_eq!(lowered.functions[0].function_index, 0);
        assert_eq!(lowered.functions[0].param_count, 2);
        assert_eq!(
            lowered.functions[0].instructions[0].op,
            SemanticOp::DeclareGlobalVar { name: 17 }
        );
        assert_eq!(
            lowered.functions[0].instructions[1].op,
            SemanticOp::Return {
                value: Value::Register(Register(0)),
            }
        );
    }

    #[test]
    fn lowers_common_runtime_and_property_families() {
        let spec = bytecode_spec(vec![
            instruction(1, "CreateEnvironment", vec![operand(0, "Reg8", None)]),
            instruction(2, "GetEnvironment", vec![operand(0, "Reg8", None), operand(1, "UInt8", None)]),
            instruction(3, "GetGlobalObject", vec![operand(0, "Reg8", None)]),
            instruction(4, "LoadParam", vec![operand(0, "Reg8", None), operand(1, "UInt8", None)]),
            instruction(
                5,
                "LoadFromEnvironment",
                vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "UInt8", None)],
            ),
            instruction(6, "LoadConstZero", vec![operand(0, "Reg8", None)]),
            instruction(7, "LoadConstUInt8", vec![operand(0, "Reg8", None), operand(1, "UInt8", None)]),
            instruction(8, "LoadConstTrue", vec![operand(0, "Reg8", None)]),
            instruction(9, "LoadConstFalse", vec![operand(0, "Reg8", None)]),
            instruction(10, "LoadConstNull", vec![operand(0, "Reg8", None)]),
            instruction(11, "Mov", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(12, "NewObject", vec![operand(0, "Reg8", None)]),
            instruction(13, "NewArray", vec![operand(0, "Reg8", None)]),
            instruction(14, "AddN", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(
                15,
                "GetByIdShort",
                vec![
                    operand(0, "Reg8", None),
                    operand(1, "Reg8", None),
                    operand(2, "UInt8", None),
                    operand(3, "UInt8", Some(OperandMeaning::StringId)),
                ],
            ),
            instruction(
                16,
                "GetByVal",
                vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)],
            ),
            instruction(
                17,
                "PutById",
                vec![
                    operand(0, "Reg8", None),
                    operand(1, "Reg8", None),
                    operand(2, "UInt8", None),
                    operand(3, "UInt16", Some(OperandMeaning::StringId)),
                ],
            ),
            instruction(
                18,
                "PutByVal",
                vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)],
            ),
            instruction(
                19,
                "PutNewOwnByIdShort",
                vec![
                    operand(0, "Reg8", None),
                    operand(1, "Reg8", None),
                    operand(2, "UInt8", Some(OperandMeaning::StringId)),
                ],
            ),
            instruction(
                20,
                "PutOwnByIndex",
                vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "UInt8", None)],
            ),
            instruction(
                21,
                "StoreToEnvironment",
                vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "UInt8", None)],
            ),
            instruction(22, "Inc", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(23, "MovLong", vec![operand(0, "Reg32", None), operand(1, "Reg8", None)]),
            instruction(24, "NewObjectWithBufferLong", vec![
                operand(0, "Reg8", None),
                operand(1, "UInt8", None),
                operand(2, "UInt8", None),
                operand(3, "UInt16", None),
                operand(4, "UInt32", None),
            ]),
            instruction(25, "NewArrayWithBufferLong", vec![
                operand(0, "Reg8", None),
                operand(1, "UInt8", None),
                operand(2, "UInt8", None),
                operand(3, "UInt32", None),
            ]),
            instruction(26, "TypeOf", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(27, "JStrictEqualLong", vec![operand(0, "Addr32", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(28, "Throw", vec![operand(0, "Reg8", None)]),
            instruction(29, "Catch", vec![operand(0, "Reg8", None)]),
            instruction(30, "GetArgumentsLength", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(31, "GetArgumentsPropByVal", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(32, "ReifyArguments", vec![operand(0, "Reg8", None)]),
            instruction(33, "LoadThisNS", vec![operand(0, "Reg8", None)]),
            instruction(34, "CreateGeneratorLongIndex", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "UInt32", Some(OperandMeaning::FunctionId)),
            ]),
            instruction(35, "ResumeGenerator", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(36, "SaveGenerator", vec![operand(0, "Reg8", None)]),
            instruction(37, "StartGenerator", vec![]),
            instruction(38, "CompleteGenerator", vec![]),
            instruction(39, "LoadFromEnvironmentL", vec![
                operand(0, "Reg32", None),
                operand(1, "Reg8", None),
                operand(2, "UInt8", None),
            ]),
            instruction(40, "StoreNPToEnvironment", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "UInt8", None),
            ]),
            instruction(41, "Construct", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(42, "CreateThis", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(43, "GetPNameList", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "Reg8", None),
                operand(3, "Reg8", None),
            ]),
            instruction(44, "GetNextPName", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "Reg8", None),
                operand(3, "Reg8", None),
                operand(4, "Reg8", None),
            ]),
            instruction(45, "NewObjectWithParent", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(46, "CreateRegExp", vec![
                operand(0, "Reg8", None),
                operand(1, "UInt32", None),
                operand(2, "UInt16", None),
                operand(3, "UInt8", None),
            ]),
            instruction(47, "IteratorClose", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(48, "IteratorNext", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(49, "IsIn", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(50, "BitAnd", vec![operand(0, "Reg8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(51, "ToNumeric", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(52, "IteratorBegin", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(53, "JNotLessEqual", vec![operand(0, "Addr8", None), operand(1, "Reg8", None), operand(2, "Reg8", None)]),
            instruction(54, "PutOwnByVal", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "Reg8", None),
                operand(3, "Reg8", None),
            ]),
            instruction(55, "StoreToEnvironmentL", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg32", None),
                operand(2, "UInt8", None),
            ]),
            instruction(56, "DelByVal", vec![
                operand(0, "Reg8", None),
                operand(1, "Reg8", None),
                operand(2, "Reg8", None),
            ]),
            instruction(57, "ToInt32", vec![operand(0, "Reg8", None), operand(1, "Reg8", None)]),
            instruction(58, "SwitchImm", vec![
                operand(0, "Reg8", None),
                operand(1, "UInt16", None),
                operand(2, "UInt16", None),
                operand(3, "Imm32", None),
                operand(4, "Imm32", None),
            ]),
            instruction(59, "CallBuiltin", vec![
                operand(0, "Reg8", None),
                operand(1, "UInt8", None),
                operand(2, "UInt8", None),
            ]),
            instruction(60, "GetNewTarget", vec![operand(0, "Reg8", None)]),
        ]);

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 0,
                    opcode: 1,
                    name: "CreateEnvironment".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(3)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CreateEnvironment { dst: Register(3) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 2,
                    opcode: 2,
                    name: "GetEnvironment".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetEnvironment {
                dst: Register(2),
                level: 0,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 5,
                    opcode: 3,
                    name: "GetGlobalObject".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetGlobalObject { dst: Register(1) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 7,
                    opcode: 4,
                    name: "LoadParam".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(9), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadParam {
                dst: Register(9),
                index: 1,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 10,
                    opcode: 5,
                    name: "LoadFromEnvironment".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(4), RawOperand::U8(2), RawOperand::U8(12)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadFromEnvironment {
                dst: Register(4),
                environment: Register(2),
                slot: 12,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 14,
                    opcode: 6,
                    name: "LoadConstZero".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(8)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadImmediate {
                dst: Register(8),
                value: Immediate::U32(0),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 16,
                    opcode: 7,
                    name: "LoadConstUInt8".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(6), RawOperand::U8(26)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadImmediate {
                dst: Register(6),
                value: Immediate::U32(26),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 19,
                    opcode: 8,
                    name: "LoadConstTrue".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(5)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadImmediate {
                dst: Register(5),
                value: Immediate::Bool(true),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 21,
                    opcode: 9,
                    name: "LoadConstFalse".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadImmediate {
                dst: Register(1),
                value: Immediate::Bool(false),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 23,
                    opcode: 10,
                    name: "LoadConstNull".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(4)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadImmediate {
                dst: Register(4),
                value: Immediate::Null,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 25,
                    opcode: 11,
                    name: "Mov".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(0), RawOperand::U8(2)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Move {
                dst: Register(0),
                src: Value::Register(Register(2)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 28,
                    opcode: 12,
                    name: "NewObject".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::NewObject { dst: Register(1) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 30,
                    opcode: 13,
                    name: "NewArray".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(7)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::NewArray { dst: Register(7) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 32,
                    opcode: 14,
                    name: "AddN".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(13), RawOperand::U8(5), RawOperand::U8(7)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Binary {
                kind: BinaryOpKind::AddN,
                dst: Register(13),
                lhs: Value::Register(Register(5)),
                rhs: Value::Register(Register(7)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 36,
                    opcode: 15,
                    name: "GetByIdShort".to_string(),
                    size: 5,
                    operands: vec![RawOperand::U8(14), RawOperand::U8(15), RawOperand::U8(4), RawOperand::U8(8)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyGet {
                kind: PropertyAccessKind::ByIdShort,
                dst: Register(14),
                object: Register(15),
                cache_index: 4,
                key: 8,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 41,
                    opcode: 16,
                    name: "GetByVal".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(11), RawOperand::U8(5), RawOperand::U8(12)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyGetByValue {
                dst: Register(11),
                object: Register(5),
                key: Value::Register(Register(12)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 45,
                    opcode: 17,
                    name: "PutById".to_string(),
                    size: 6,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(2), RawOperand::U8(3), RawOperand::U16(10)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyPut {
                kind: PropertyAccessKind::ById,
                object: Register(1),
                value: Value::Register(Register(2)),
                cache_index: 3,
                key: 10,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 51,
                    opcode: 18,
                    name: "PutByVal".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(3), RawOperand::U8(12), RawOperand::U8(11)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyPutByValue {
                object: Register(3),
                key: Value::Register(Register(12)),
                value: Value::Register(Register(11)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 55,
                    opcode: 19,
                    name: "PutNewOwnByIdShort".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(10), RawOperand::U8(123)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyDefine {
                kind: PropertyDefineKind::NewOwnByIdShort,
                object: Register(1),
                value: Value::Register(Register(10)),
                key: 123,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 59,
                    opcode: 20,
                    name: "PutOwnByIndex".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(4), RawOperand::U8(7), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyPutIndex {
                object: Register(4),
                value: Value::Register(Register(7)),
                index: 0,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 63,
                    opcode: 21,
                    name: "StoreToEnvironment".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(9), RawOperand::U8(4)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::StoreToEnvironment {
                environment: Register(2),
                value: Value::Register(Register(9)),
                slot: 4,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 67,
                    opcode: 22,
                    name: "Inc".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Increment {
                dst: Register(2),
                src: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 70,
                    opcode: 23,
                    name: "MovLong".to_string(),
                    size: 6,
                    operands: vec![RawOperand::U32(445), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Move {
                dst: Register(445),
                src: Value::Register(Register(0)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 76,
                    opcode: 24,
                    name: "NewObjectWithBufferLong".to_string(),
                    size: 9,
                    operands: vec![RawOperand::U8(5), RawOperand::U8(7), RawOperand::U8(6), RawOperand::U16(6350), RawOperand::U32(65579)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::NewObjectWithBuffer {
                dst: Register(5),
                key_count: 7,
                value_count: 6,
                key_buffer_index: 6350,
                shape_table_index: 65579,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 85,
                    opcode: 25,
                    name: "NewArrayWithBufferLong".to_string(),
                    size: 8,
                    operands: vec![RawOperand::U8(5), RawOperand::U8(13), RawOperand::U8(13), RawOperand::U32(65555)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::NewArrayWithBuffer {
                dst: Register(5),
                min_size: 13,
                max_size: 13,
                buffer_index: 65555,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 93,
                    opcode: 26,
                    name: "TypeOf".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Unary {
                kind: UnaryOpKind::TypeOf,
                dst: Register(1),
                operand: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 96,
                    opcode: 27,
                    name: "JStrictEqualLong".to_string(),
                    size: 6,
                    operands: vec![RawOperand::I32(224), RawOperand::U8(1), RawOperand::U8(3)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Branch {
                kind: BranchKind::StrictEqual,
                target: 320,
                args: vec![Value::Register(Register(1)), Value::Register(Register(3))],
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 102,
                    opcode: 28,
                    name: "Throw".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Throw {
                value: Value::Register(Register(0)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 104,
                    opcode: 29,
                    name: "Catch".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(7)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Catch { dst: Register(7) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 106,
                    opcode: 30,
                    name: "GetArgumentsLength".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(2)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetArgumentsLength {
                dst: Register(1),
                arguments: Register(2),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 109,
                    opcode: 31,
                    name: "GetArgumentsPropByVal".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(3), RawOperand::U8(1), RawOperand::U8(2)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetArgumentsPropByValue {
                dst: Register(3),
                arguments: Register(1),
                key: Value::Register(Register(2)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 113,
                    opcode: 32,
                    name: "ReifyArguments".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(2)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::ReifyArguments { dst: Register(2) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 115,
                    opcode: 33,
                    name: "LoadThisNS".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(5)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadThisNS { dst: Register(5) }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 117,
                    opcode: 34,
                    name: "CreateGeneratorLongIndex".to_string(),
                    size: 7,
                    operands: vec![RawOperand::U8(0), RawOperand::U8(0), RawOperand::U32(66064)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CreateGenerator {
                dst: Register(0),
                environment: Register(0),
                function: 66064,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 124,
                    opcode: 35,
                    name: "ResumeGenerator".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(2)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::ResumeGenerator {
                dst: Register(1),
                value: Value::Register(Register(2)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 127,
                    opcode: 36,
                    name: "SaveGenerator".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(4)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::SaveGenerator {
                value: Value::Register(Register(4)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 129,
                    opcode: 37,
                    name: "StartGenerator".to_string(),
                    size: 1,
                    operands: vec![],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::StartGenerator
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 130,
                    opcode: 38,
                    name: "CompleteGenerator".to_string(),
                    size: 1,
                    operands: vec![],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CompleteGenerator
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 131,
                    opcode: 39,
                    name: "LoadFromEnvironmentL".to_string(),
                    size: 6,
                    operands: vec![RawOperand::U32(445), RawOperand::U8(0), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::LoadFromEnvironment {
                dst: Register(445),
                environment: Register(0),
                slot: 1,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 137,
                    opcode: 40,
                    name: "StoreNPToEnvironment".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(9), RawOperand::U8(4)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::StoreToEnvironment {
                environment: Register(2),
                value: Value::Register(Register(9)),
                slot: 4,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 141,
                    opcode: 41,
                    name: "Construct".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(1), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Construct {
                dst: Register(1),
                callee: Register(1),
                argument_count: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 145,
                    opcode: 42,
                    name: "CreateThis".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(3), RawOperand::U8(3), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CreateThis {
                dst: Register(3),
                callee: Register(3),
                new_target: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 149,
                    opcode: 43,
                    name: "GetPNameList".to_string(),
                    size: 5,
                    operands: vec![RawOperand::U8(10), RawOperand::U8(9), RawOperand::U8(8), RawOperand::U8(7)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetPNameList {
                dst: Register(10),
                iterator: Register(9),
                base: Register(8),
                index: Register(7),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 154,
                    opcode: 44,
                    name: "GetNextPName".to_string(),
                    size: 6,
                    operands: vec![RawOperand::U8(6), RawOperand::U8(10), RawOperand::U8(9), RawOperand::U8(8), RawOperand::U8(7)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetNextPName {
                dst: Register(6),
                iterator: Register(10),
                base: Register(9),
                index: Register(8),
                size: Register(7),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 160,
                    opcode: 45,
                    name: "NewObjectWithParent".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(11), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::NewObjectWithParent {
                dst: Register(11),
                parent: Register(1),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 163,
                    opcode: 46,
                    name: "CreateRegExp".to_string(),
                    size: 8,
                    operands: vec![RawOperand::U8(1), RawOperand::U32(160134), RawOperand::U16(397), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CreateRegExp {
                dst: Register(1),
                pattern_id: 160134,
                flags_id: 397,
                regexp_id: 0,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 171,
                    opcode: 47,
                    name: "IteratorClose".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::IteratorClose {
                iterator: Register(2),
                value: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 174,
                    opcode: 48,
                    name: "IteratorNext".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(4), RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::IteratorNext {
                dst: Register(4),
                iterator: Register(2),
                source: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 178,
                    opcode: 49,
                    name: "IsIn".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(4), RawOperand::U8(13)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Binary {
                kind: BinaryOpKind::IsIn,
                dst: Register(1),
                lhs: Value::Register(Register(4)),
                rhs: Value::Register(Register(13)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 182,
                    opcode: 50,
                    name: "BitAnd".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Binary {
                kind: BinaryOpKind::BitAnd,
                dst: Register(1),
                lhs: Value::Register(Register(2)),
                rhs: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 186,
                    opcode: 51,
                    name: "ToNumeric".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Unary {
                kind: UnaryOpKind::ToNumeric,
                dst: Register(1),
                operand: Value::Register(Register(0)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 189,
                    opcode: 52,
                    name: "IteratorBegin".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::IteratorBegin {
                dst: Register(2),
                source: Register(1),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 192,
                    opcode: 53,
                    name: "JNotLessEqual".to_string(),
                    size: 4,
                    operands: vec![RawOperand::I8(12), RawOperand::U8(4), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Branch {
                kind: BranchKind::NotLessEqual,
                target: 204,
                args: vec![Value::Register(Register(4)), Value::Register(Register(1))],
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 196,
                    opcode: 54,
                    name: "PutOwnByVal".to_string(),
                    size: 5,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(7), RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::PropertyPutOwnByValue {
                object: Register(1),
                key: Value::Register(Register(7)),
                value: Value::Register(Register(2)),
                enumerable: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 201,
                    opcode: 55,
                    name: "StoreToEnvironmentL".to_string(),
                    size: 7,
                    operands: vec![RawOperand::U8(1), RawOperand::U32(256), RawOperand::U8(0)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::StoreToEnvironment {
                environment: Register(1),
                value: Value::Register(Register(256)),
                slot: 0,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 208,
                    opcode: 56,
                    name: "DelByVal".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(0), RawOperand::U8(0), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::DeletePropertyByValue {
                dst: Register(0),
                object: Register(0),
                key: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 212,
                    opcode: 57,
                    name: "ToInt32".to_string(),
                    size: 3,
                    operands: vec![RawOperand::U8(2), RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::Unary {
                kind: UnaryOpKind::ToInt32,
                dst: Register(2),
                operand: Value::Register(Register(1)),
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 215,
                    opcode: 58,
                    name: "SwitchImm".to_string(),
                    size: 9,
                    operands: vec![RawOperand::U8(1), RawOperand::U16(320), RawOperand::U16(316), RawOperand::I32(0), RawOperand::I32(25)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::SwitchImm {
                input: Value::Register(Register(1)),
                table_offset: 320,
                default_offset: 316,
                min_case: 0,
                max_case: 25,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 224,
                    opcode: 59,
                    name: "CallBuiltin".to_string(),
                    size: 4,
                    operands: vec![RawOperand::U8(1), RawOperand::U8(49), RawOperand::U8(3)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::CallBuiltin {
                dst: Register(1),
                builtin: 49,
                argc: 3,
            }
        );

        assert_eq!(
            lower_instruction(
                &RawInstruction {
                    offset: 228,
                    opcode: 60,
                    name: "GetNewTarget".to_string(),
                    size: 2,
                    operands: vec![RawOperand::U8(1)],
                },
                &spec,
            )
            .unwrap()
            .op,
            SemanticOp::GetNewTarget { dst: Register(1) }
        );
    }
}

//! Basic blocks retain original instruction addresses; no guessed structuring.
use crate::Error;
use mercury_ir::{RawFunction, RawInstruction, RawOperand};
use std::collections::{BTreeMap, BTreeSet};

pub struct Block<'a> {
    pub start: u32,
    pub instructions: &'a [RawInstruction],
    pub next: Option<u32>,
}
pub fn target(instruction: &RawInstruction) -> Result<u32, Error> {
    relative_target(instruction, 0)
}
pub fn relative_target(instruction: &RawInstruction, operand: usize) -> Result<u32, Error> {
    let displacement = match instruction.operands.get(operand) {
        Some(RawOperand::I8(value)) => i64::from(*value),
        Some(RawOperand::I32(value)) => i64::from(*value),
        _ => {
            return Err(Error::Bytecode(format!(
                "invalid jump at {}",
                instruction.offset
            )));
        }
    };
    u32::try_from(i64::from(instruction.offset) + displacement)
        .map_err(|_| Error::Bytecode("jump target overflows function address space".into()))
}
pub fn blocks(function: &RawFunction) -> Result<Vec<Block<'_>>, Error> {
    if function.instructions.is_empty() {
        return Err(Error::Bytecode("empty function".into()));
    }
    let offsets: BTreeMap<_, _> = function
        .instructions
        .iter()
        .enumerate()
        .map(|(i, op)| (op.offset, i))
        .collect();
    let mut leaders = BTreeSet::from([0]);
    for handler in &function.exception_handlers {
        for boundary in [handler.start, handler.target] {
            if !offsets.contains_key(&boundary) {
                return Err(Error::Bytecode(format!(
                    "exception handler boundary {boundary} is not an instruction"
                )));
            }
            leaders.insert(boundary);
        }
        if handler.end < function.bytecode_size_in_bytes {
            if !offsets.contains_key(&handler.end) {
                return Err(Error::Bytecode(format!(
                    "exception handler boundary {} is not an instruction",
                    handler.end
                )));
            }
            leaders.insert(handler.end);
        } else if handler.end != function.bytecode_size_in_bytes {
            return Err(Error::Bytecode(format!(
                "exception handler end {} is outside the function",
                handler.end
            )));
        }
        if handler.start >= handler.end {
            return Err(Error::Bytecode("empty exception handler range".into()));
        }
    }
    for (i, op) in function.instructions.iter().enumerate() {
        if op.name.starts_with('J') {
            let dest = target(op)?;
            if !offsets.contains_key(&dest) {
                return Err(Error::Bytecode(format!(
                    "jump at {} targets non-instruction {dest}",
                    op.offset
                )));
            }
            leaders.insert(dest);
        }
        if op.name == "SwitchImm" {
            let table = function
                .switch_tables
                .iter()
                .find(|table| table.instruction_offset == op.offset)
                .ok_or_else(|| Error::Bytecode(format!("missing switch table at {}", op.offset)))?;
            let mut targets = table
                .displacements
                .iter()
                .map(|displacement| switch_target(op.offset, *displacement))
                .collect::<Result<Vec<_>, _>>()?;
            targets.push(relative_target(op, 2)?);
            for dest in targets {
                if !offsets.contains_key(&dest) {
                    return Err(Error::Bytecode(format!(
                        "switch at {} targets non-instruction {dest}",
                        op.offset
                    )));
                }
                leaders.insert(dest);
            }
        }
        if (op.name.starts_with('J')
            || op.name == "SwitchImm"
            || matches!(op.name.as_str(), "Ret" | "Throw"))
            && i + 1 < function.instructions.len()
        {
            leaders.insert(function.instructions[i + 1].offset);
        }
    }
    let leaders: Vec<_> = leaders.into_iter().collect();
    leaders
        .iter()
        .enumerate()
        .map(|(i, start)| {
            let from = *offsets
                .get(start)
                .ok_or_else(|| Error::Bytecode("function does not start at offset zero".into()))?;
            let next = leaders.get(i + 1).copied();
            let to = next
                .map(|next| offsets[&next])
                .unwrap_or(function.instructions.len());
            Ok(Block {
                start: *start,
                instructions: &function.instructions[from..to],
                next,
            })
        })
        .collect()
}

pub fn switch_target(instruction_offset: u32, displacement: i32) -> Result<u32, Error> {
    u32::try_from(i64::from(instruction_offset) + i64::from(displacement))
        .map_err(|_| Error::Bytecode("switch target overflows function address space".into()))
}

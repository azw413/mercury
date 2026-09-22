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
    let displacement = match instruction.operands.first() {
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
        if (op.name.starts_with('J') || matches!(op.name.as_str(), "Ret" | "Throw"))
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

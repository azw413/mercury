use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mercury_spec::{HermesSpec, OperandMeaning};

#[derive(Debug, Clone)]
/// Summary of how a generated Mercury spec compares with `hermes-dec`.
pub struct HermesDecComparison {
    pub opcode_module_path: PathBuf,
    pub opcode_count_matches: bool,
    pub opcode_mismatches: Vec<String>,
    pub file_header_mismatches: Vec<String>,
}

#[derive(Debug, Clone)]
struct HermesDecInstruction {
    opcode: u16,
    name: String,
    operands: Vec<String>,
    meanings: Vec<Option<OperandMeaning>>,
    has_ret_target: bool,
}

/// Compares a generated spec with the matching `hermes-dec` opcode and header tables.
pub fn compare_against_hermes_dec(
    spec: &HermesSpec,
    hermes_dec_root: impl AsRef<Path>,
) -> Result<HermesDecComparison> {
    let hermes_dec_root = hermes_dec_root.as_ref();
    let opcode_module_path = hermes_dec_root.join(format!(
        "src/hermes_dec/parsers/hbc_opcodes/hbc{}.py",
        spec.bytecode_version
    ));
    let source = fs::read_to_string(&opcode_module_path).with_context(|| {
        format!(
            "failed to read hermes-dec opcode module {}",
            opcode_module_path.display()
        )
    })?;

    let reference = parse_hermes_dec_opcode_module(&source);
    let mut opcode_mismatches = Vec::new();

    if spec.bytecode.instructions.len() != reference.len() {
        opcode_mismatches.push(format!(
            "instruction count differs: mercury={} hermes-dec={}",
            spec.bytecode.instructions.len(),
            reference.len()
        ));
    }

    for (index, (left, right)) in spec
        .bytecode
        .instructions
        .iter()
        .zip(reference.iter())
        .enumerate()
    {
        if left.opcode != right.opcode || left.name != right.name {
            opcode_mismatches.push(format!(
                "opcode {} differs: mercury={}#{} hermes-dec={}#{}",
                index, left.name, left.opcode, right.name, right.opcode
            ));
            continue;
        }

        let left_operands = left.operands.iter().map(|op| op.kind.as_str()).collect::<Vec<_>>();
        let right_operands = right.operands.iter().map(String::as_str).collect::<Vec<_>>();
        if left_operands != right_operands {
            opcode_mismatches.push(format!(
                "operands differ for {}: mercury={:?} hermes-dec={:?}",
                left.name, left_operands, right_operands
            ));
        }

        let left_meanings = left.operands.iter().map(|op| op.meaning.clone()).collect::<Vec<_>>();
        if left_meanings != right.meanings {
            opcode_mismatches.push(format!(
                "operand meanings differ for {}: mercury={:?} hermes-dec={:?}",
                left.name, left_meanings, right.meanings
            ));
        }

        if left.flags.has_ret_target != right.has_ret_target {
            opcode_mismatches.push(format!(
                "ret-target flag differs for {}: mercury={} hermes-dec={}",
                left.name, left.flags.has_ret_target, right.has_ret_target
            ));
        }
    }

    let file_header_mismatches = compare_file_header_fields(spec.bytecode_version, spec);

    Ok(HermesDecComparison {
        opcode_module_path,
        opcode_count_matches: spec.bytecode.instructions.len() == reference.len(),
        opcode_mismatches,
        file_header_mismatches,
    })
}

fn parse_hermes_dec_opcode_module(source: &str) -> Vec<HermesDecInstruction> {
    let mut instructions = Vec::<HermesDecInstruction>::new();
    let mut current = Vec::<String>::new();
    let mut paren_depth = 0i32;

    for line in source.lines() {
        let trimmed = line.trim();
        if current.is_empty() {
            if trimmed.contains(" = Instruction(") {
                current.push(trimmed.to_owned());
                paren_depth = count_parens(trimmed);
                if paren_depth <= 0 {
                    if let Some(instruction) = parse_instruction_chunk(&current.join(" ")) {
                        instructions.push(instruction);
                    }
                    current.clear();
                }
            }
            continue;
        }

        current.push(trimmed.to_owned());
        paren_depth += count_parens(trimmed);
        if paren_depth <= 0 {
            if let Some(instruction) = parse_instruction_chunk(&current.join(" ")) {
                instructions.push(instruction);
            }
            current.clear();
            paren_depth = 0;
        }
    }

    for line in source.lines() {
        let line = line.trim();
        if let Some((name, operand_index, meaning)) = parse_py_operand_meaning(line) {
            if let Some(instruction) = instructions.iter_mut().find(|inst| inst.name == name) {
                let index = operand_index as usize;
                if index < instruction.meanings.len() {
                    instruction.meanings[index] = Some(meaning);
                }
            }
        }

        if let Some(name) = line.strip_suffix(".has_ret_target = True") {
            if let Some(instruction) = instructions.iter_mut().find(|inst| inst.name == name) {
                instruction.has_ret_target = true;
            }
        }
    }

    instructions.sort_by_key(|inst| inst.opcode);
    instructions
}

fn count_parens(line: &str) -> i32 {
    let opens = line.chars().filter(|ch| *ch == '(').count() as i32;
    let closes = line.chars().filter(|ch| *ch == ')').count() as i32;
    opens - closes
}

fn parse_instruction_chunk(chunk: &str) -> Option<HermesDecInstruction> {
    let (binding, _) = chunk.split_once(" = Instruction(")?;
    let name = binding.trim().to_owned();
    let (_, after_quote) = chunk.split_once("',")?;
    let after_quote = after_quote.trim_start_matches(',').trim();
    let (opcode_text, _) = after_quote.split_once(',')?;
    let opcode = opcode_text.trim().parse::<u16>().ok()?;
    let (_, after_operands_start) = chunk.split_once('[')?;
    let (operand_text, _) = after_operands_start.split_once(']')?;
    let operands = operand_text
        .split(", ")
        .filter(|item| !item.trim().is_empty())
        .map(|item| item.trim().to_owned())
        .collect::<Vec<_>>();

    Some(HermesDecInstruction {
        opcode,
        name,
        meanings: vec![None; operands.len()],
        operands,
        has_ret_target: false,
    })
}

fn parse_py_operand_meaning(line: &str) -> Option<(String, u8, OperandMeaning)> {
    let (lhs, rhs) = line.split_once(".operand_meaning = OperandMeaning.")?;
    let (name, operand_suffix) = lhs.split_once(".operands[")?;
    let operand_index = operand_suffix.trim_end_matches(']').parse::<u8>().ok()?;
    let meaning = match rhs {
        "bigint_id" => OperandMeaning::BigIntId,
        "function_id" => OperandMeaning::FunctionId,
        "string_id" => OperandMeaning::StringId,
        _ => return None,
    };
    Some((name.to_owned(), operand_index, meaning))
}

fn compare_file_header_fields(bytecode_version: u32, spec: &HermesSpec) -> Vec<String> {
    let expected = expected_file_header_core_fields_from_hermes_dec(bytecode_version);
    let actual = spec
        .container
        .file_header
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();

    if actual.starts_with(&expected) {
        return Vec::new();
    }

    vec![format!(
        "file header core fields differ: mercury={:?} hermes-dec={:?}",
        actual, expected
    )]
}

fn expected_file_header_core_fields_from_hermes_dec(bytecode_version: u32) -> Vec<&'static str> {
    let mut fields = vec![
        "magic",
        "version",
        "sourceHash",
        "fileLength",
        "globalCodeIndex",
        "functionCount",
        "stringKindCount",
        "identifierCount",
        "stringCount",
        "overflowStringCount",
        "stringStorageSize",
    ];

    if bytecode_version >= 87 {
        fields.extend(["bigIntCount", "bigIntStorageSize"]);
    }

    fields.extend([
        "regExpCount",
        "regExpStorageSize",
        "arrayBufferSize",
        "objKeyBufferSize",
        "objValueBufferSize",
    ]);

    if bytecode_version < 78 {
        fields.push("cjsModuleOffset");
    } else {
        fields.push("segmentID");
    }

    fields.push("cjsModuleCount");

    if bytecode_version >= 84 {
        fields.push("functionSourceCount");
    }

    fields.push("debugInfoOffset");

    fields
}

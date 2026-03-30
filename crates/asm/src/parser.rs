use crate::ast::{
    AssemblyStringKind, SemanticAssemblyFunction, SemanticAssemblyInstruction,
    SemanticAssemblyModule, SemanticAssemblyStatement, SemanticObjectShapeEntry, SemanticOperand,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AssemblyParseError {
    #[error("invalid directive at line {line}: {text}")]
    InvalidDirective { line: usize, text: String },
    #[error("invalid function header at line {line}: {text}")]
    InvalidFunctionHeader { line: usize, text: String },
    #[error("unexpected .end at line {line}")]
    UnexpectedEnd { line: usize },
    #[error("unterminated section at end of file")]
    UnterminatedSection,
    #[error("invalid instruction at line {line}: {text}")]
    InvalidInstruction { line: usize, text: String },
    #[error("invalid string literal at line {line}: {text}")]
    InvalidStringLiteral { line: usize, text: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Strings,
    LiteralValueBuffer,
    ObjectKeyBuffer,
    ObjectShapeTable,
    Function,
}

pub fn parse_semantic_assembly(input: &str) -> Result<SemanticAssemblyModule, AssemblyParseError> {
    let mut module = SemanticAssemblyModule {
        bytecode_version: None,
        strings: Vec::new(),
        string_kinds: Vec::new(),
        literal_value_buffer: Vec::new(),
        object_key_buffer: Vec::new(),
        object_shape_table: Vec::new(),
        functions: Vec::new(),
    };
    let mut section: Option<Section> = None;
    let mut current_function: Option<SemanticAssemblyFunction> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if matches!(line, "view semantic")
            || line.starts_with("input ")
            || line.starts_with("function_count ")
        {
            continue;
        }
        if let Some(rest) = line.strip_prefix("bytecode_version ") {
            module.bytecode_version = rest.parse().ok();
            continue;
        }

        if line == ".strings" {
            if section.is_some() {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                });
            }
            section = Some(Section::Strings);
            continue;
        }

        if matches!(line, ".literal_value_buffer" | ".array_buffer") {
            if section.is_some() {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                });
            }
            section = Some(Section::LiteralValueBuffer);
            continue;
        }

        if line == ".object_key_buffer" {
            if section.is_some() {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                });
            }
            section = Some(Section::ObjectKeyBuffer);
            continue;
        }

        if matches!(line, ".object_shape_table" | ".object_value_buffer") {
            if section.is_some() {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                });
            }
            section = Some(Section::ObjectShapeTable);
            continue;
        }

        if line.starts_with(".function ") {
            if section.is_some() {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                });
            }
            current_function = Some(parse_function_header(line_no, line)?);
            section = Some(Section::Function);
            continue;
        }

        if line == ".end" {
            match section.take() {
                Some(Section::Strings) => {}
                Some(Section::LiteralValueBuffer) => {}
                Some(Section::ObjectKeyBuffer) => {}
                Some(Section::ObjectShapeTable) => {}
                Some(Section::Function) => {
                    module.functions.push(
                        current_function
                            .take()
                            .expect("function section should have a function"),
                    );
                }
                None => return Err(AssemblyParseError::UnexpectedEnd { line: line_no }),
            }
            continue;
        }

        match section {
            Some(Section::Strings) => {
                let (kind, literal) = if let Some((lhs, rhs)) = line.split_once('=') {
                    let lhs = lhs.trim();
                    let kind = if lhs.starts_with('i') {
                        AssemblyStringKind::Identifier
                    } else {
                        AssemblyStringKind::String
                    };
                    (kind, rhs.trim())
                } else {
                    (AssemblyStringKind::String, line)
                };
                module.strings.push(decode_string_literal(line_no, literal)?);
                module.string_kinds.push(kind);
            }
            Some(Section::LiteralValueBuffer) => {
                parse_hex_bytes_into(line_no, line, &mut module.literal_value_buffer)?;
            }
            Some(Section::ObjectKeyBuffer) => {
                parse_hex_bytes_into(line_no, line, &mut module.object_key_buffer)?;
            }
            Some(Section::ObjectShapeTable) => {
                module.object_shape_table.push(parse_shape_table_entry(line_no, line)?);
            }
            Some(Section::Function) => {
                let function = current_function
                    .as_mut()
                    .expect("function section should have a function");
                if let Some(label) = line.strip_suffix(':') {
                    function
                        .body
                        .push(SemanticAssemblyStatement::Label(label.to_owned()));
                } else {
                    function.body.push(SemanticAssemblyStatement::Instruction(
                        parse_instruction(line_no, line)?,
                    ));
                }
            }
            None => {
                return Err(AssemblyParseError::InvalidDirective {
                    line: line_no,
                    text: line.to_owned(),
                })
            }
        }
    }

    if section.is_some() {
        return Err(AssemblyParseError::UnterminatedSection);
    }

    Ok(module)
}

fn parse_function_header(
    line_no: usize,
    line: &str,
) -> Result<SemanticAssemblyFunction, AssemblyParseError> {
    let mut symbol = None;
    let mut name = None;
    let mut params = None;
    let mut frame = None;
    let mut env = None;

    let rest = line
        .strip_prefix(".function ")
        .ok_or_else(|| AssemblyParseError::InvalidFunctionHeader {
            line: line_no,
            text: line.to_owned(),
        })?;

    for token in rest.split_whitespace() {
        if let Some(value) = token.strip_prefix("name=") {
            name = Some(value.trim_matches('"').trim_start_matches('@').to_owned());
        } else if let Some(value) = token.strip_prefix("params=") {
            params = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("frame=") {
            frame = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("env=") {
            env = value.parse().ok();
        } else if token.starts_with('@') && symbol.is_none() {
            symbol = Some(token.trim_start_matches('@').to_owned());
        }
    }

    let symbol = symbol
        .clone()
        .or_else(|| name.clone())
        .ok_or_else(|| AssemblyParseError::InvalidFunctionHeader {
            line: line_no,
            text: line.to_owned(),
        })?;
    let name = name.unwrap_or_else(|| symbol.clone());

    Ok(SemanticAssemblyFunction {
        symbol,
        name,
        params: params.ok_or_else(|| AssemblyParseError::InvalidFunctionHeader {
            line: line_no,
            text: line.to_owned(),
        })?,
        frame: frame.ok_or_else(|| AssemblyParseError::InvalidFunctionHeader {
            line: line_no,
            text: line.to_owned(),
        })?,
        env: env.ok_or_else(|| AssemblyParseError::InvalidFunctionHeader {
            line: line_no,
            text: line.to_owned(),
        })?,
        body: Vec::new(),
    })
}

fn parse_instruction(
    line_no: usize,
    line: &str,
) -> Result<SemanticAssemblyInstruction, AssemblyParseError> {
    let (offset, body) = if let Some((prefix, rest)) = line.split_once(':') {
        if prefix.chars().all(|ch| ch.is_ascii_hexdigit()) {
            let offset = u32::from_str_radix(prefix, 16).map_err(|_| {
                AssemblyParseError::InvalidInstruction {
                    line: line_no,
                    text: line.to_owned(),
                }
            })?;
            (Some(offset), rest.trim())
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };

    let (mnemonic, operands) = if let Some((mnemonic, rest)) = body.split_once(' ') {
        (mnemonic.to_owned(), parse_operands(line_no, rest.trim())?)
    } else {
        (body.to_owned(), Vec::new())
    };

    if mnemonic.is_empty() {
        return Err(AssemblyParseError::InvalidInstruction {
            line: line_no,
            text: line.to_owned(),
        });
    }

    Ok(SemanticAssemblyInstruction {
        offset,
        mnemonic,
        operands,
    })
}

fn parse_operands(
    line_no: usize,
    text: &str,
) -> Result<Vec<SemanticOperand>, AssemblyParseError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;

    for ch in text.chars() {
        if in_string {
            current.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            ',' => {
                push_operand(line_no, &mut out, &current)?;
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    push_operand(line_no, &mut out, &current)?;
    Ok(out)
}

fn parse_hex_bytes_into(
    line_no: usize,
    line: &str,
    out: &mut Vec<u8>,
) -> Result<(), AssemblyParseError> {
    for token in line.split_whitespace() {
        let byte = u8::from_str_radix(token, 16).map_err(|_| AssemblyParseError::InvalidDirective {
            line: line_no,
            text: line.to_owned(),
        })?;
        out.push(byte);
    }
    Ok(())
}

fn parse_shape_table_entry(
    line_no: usize,
    line: &str,
) -> Result<SemanticObjectShapeEntry, AssemblyParseError> {
    let mut parts = line.split(',').map(str::trim);
    let key_buffer_offset = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AssemblyParseError::InvalidDirective {
            line: line_no,
            text: line.to_owned(),
        })?;
    let num_props = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| AssemblyParseError::InvalidDirective {
            line: line_no,
            text: line.to_owned(),
        })?;
    if parts.next().is_some() {
        return Err(AssemblyParseError::InvalidDirective {
            line: line_no,
            text: line.to_owned(),
        });
    }
    Ok(SemanticObjectShapeEntry {
        key_buffer_offset,
        num_props,
    })
}

fn push_operand(
    line_no: usize,
    out: &mut Vec<SemanticOperand>,
    raw: &str,
) -> Result<(), AssemblyParseError> {
    let token = raw.trim();
    if token.is_empty() {
        return Ok(());
    }

    let operand = if let Some(value) = token.strip_prefix('r') {
        if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) {
            SemanticOperand::Register(value.parse().map_err(|_| {
                AssemblyParseError::InvalidInstruction {
                    line: line_no,
                    text: token.to_owned(),
                }
            })?)
        } else {
            parse_non_register_operand(line_no, token)?
        }
    } else {
        parse_non_register_operand(line_no, token)?
    };

    out.push(operand);
    Ok(())
}

fn parse_non_register_operand(
    line_no: usize,
    token: &str,
) -> Result<SemanticOperand, AssemblyParseError> {
    if token.starts_with('"') {
        return Ok(SemanticOperand::String(
            parse_string_literal(line_no, token)?.to_owned(),
        ));
    }
    if let Some(value) = token.strip_prefix('@') {
        return Ok(SemanticOperand::FunctionRef(value.to_owned()));
    }
    if token.starts_with('L') {
        return Ok(SemanticOperand::Label(token.to_owned()));
    }
    if let Ok(value) = token.parse::<i64>() {
        return Ok(SemanticOperand::Integer(value));
    }
    Ok(SemanticOperand::Bareword(token.to_owned()))
}

fn parse_string_literal<'a>(
    line_no: usize,
    token: &'a str,
) -> Result<&'a str, AssemblyParseError> {
    if !(token.starts_with('"') && token.ends_with('"')) {
        return Err(AssemblyParseError::InvalidStringLiteral {
            line: line_no,
            text: token.to_owned(),
        });
    }
    let _: String = serde_json::from_str(token).map_err(|_| AssemblyParseError::InvalidStringLiteral {
        line: line_no,
        text: token.to_owned(),
    })?;
    Ok(token)
}

fn decode_string_literal(line_no: usize, token: &str) -> Result<String, AssemblyParseError> {
    parse_string_literal(line_no, token)?;
    serde_json::from_str(token).map_err(|_| AssemblyParseError::InvalidStringLiteral {
        line: line_no,
        text: token.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_semantic_decode_shape() {
        let input = r#"
# mercury decode
input test/hex.hbc
bytecode_version 96
view semantic
function_count 2

.strings
  s0 = ""
  s9 = "encode"
.end

.function 0 name=global params=1 frame=3 env=0
  0000: declare_global_var "encode"
  0005: create_environment r0
  0007: create_closure r2, r0, @encode
L1:
  000c: branch_false r10, L2
.end

.function @encode params=2 frame=25 env=0
  load_param r9, 1
  return r0
.end
"#;

        let module = parse_semantic_assembly(input).unwrap();

        assert_eq!(module.bytecode_version, Some(96));
        assert_eq!(module.strings.len(), 2);
        assert_eq!(module.functions.len(), 2);
        assert_eq!(module.functions[0].name, "global");
        assert_eq!(module.functions[1].name, "encode");
        assert_eq!(
            module.functions[0].body[0],
            SemanticAssemblyStatement::Instruction(SemanticAssemblyInstruction {
                offset: Some(0),
                mnemonic: "declare_global_var".to_owned(),
                operands: vec![SemanticOperand::String("\"encode\"".to_owned())],
            })
        );
        assert_eq!(
            module.functions[0].body[2],
            SemanticAssemblyStatement::Instruction(SemanticAssemblyInstruction {
                offset: Some(7),
                mnemonic: "create_closure".to_owned(),
                operands: vec![
                    SemanticOperand::Register(2),
                    SemanticOperand::Register(0),
                    SemanticOperand::FunctionRef("encode".to_owned()),
                ],
            })
        );
        assert_eq!(
            module.functions[0].body[3],
            SemanticAssemblyStatement::Label("L1".to_owned())
        );
    }

    #[test]
    fn rejects_unterminated_sections() {
        let err = parse_semantic_assembly(".strings\n  \"x\"\n").unwrap_err();
        assert_eq!(err, AssemblyParseError::UnterminatedSection);
    }
}

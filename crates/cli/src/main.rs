use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use mercury_binary::{decode_raw_module, parse_hbc_container_with_spec};
use mercury_ir::{
    lower_module, BinaryOpKind, BranchKind, Immediate, PropertyAccessKind, RawFunction,
    PropertyDefineKind, RawInstruction, RawOperand, SemanticFunction, SemanticInstruction,
    SemanticModule, SemanticOp, UnaryOpKind, Value,
};
use mercury_spec_builtin::{load_spec, supported_versions};
use mercury_spec_extract::{Extractor, ExtractorConfig};
use mercury_spec_extract::hermes_dec::compare_against_hermes_dec;

#[derive(Debug, Parser)]
#[command(name = "mercury")]
#[command(about = "Hermes bytecode reverse engineering toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Versions,
    Decode {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = DecodeFormat::Raw)]
        format: DecodeFormat,
    },
    ExtractSpec {
        #[arg(long, default_value = "../hermes")]
        hermes_repo: String,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value = "spec/generated")]
        output_dir: String,
        #[arg(long)]
        compare_hermes_dec: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DecodeFormat {
    Raw,
    Semantic,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Versions => {
            for version in supported_versions() {
                println!("{version}");
            }
        }
        Command::Decode {
            input,
            output,
            format,
        } => {
            let bytes = fs::read(&input)
                .with_context(|| format!("failed to read {}", input.display()))?;
            let version = detect_bytecode_version(&bytes)?;
            let spec = load_spec(version)
                .with_context(|| format!("no embedded spec for bytecode version {version}"))?;
            let container = parse_hbc_container_with_spec(&bytes, &spec.container)
                .with_context(|| format!("failed to parse {}", input.display()))?;
            let raw = decode_raw_module(&container, &bytes, &spec.bytecode)
                .with_context(|| format!("failed to decode {}", input.display()))?;
            let body = match format {
                DecodeFormat::Raw => render_raw_module(&input, &raw, &container, &spec),
                DecodeFormat::Semantic => {
                    let semantic = lower_module(&raw, &spec.bytecode)
                        .with_context(|| format!("failed to lower {}", input.display()))?;
                    render_semantic_module(&input, &semantic, &raw, &container)
                }
            };

            if let Some(output) = output {
                fs::write(&output, body)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                print!("{body}");
            }
        }
        Command::ExtractSpec {
            hermes_repo,
            tag,
            output_dir,
            compare_hermes_dec,
        } => {
            let extractor = Extractor::new(ExtractorConfig { hermes_repo });
            if let Some(tag) = tag {
                let spec = extractor.extract_tag(&tag)?;
                let output_path = format!("{output_dir}/hbc{}.json", spec.bytecode_version);
                extractor.write_json(&spec, &output_path)?;
                println!(
                    "wrote {}",
                    output_path,
                );
                println!(
                    "bytecode_version={} source_tag={} instructions={} file_header_fields={} function_header_fields={}",
                    spec.bytecode_version,
                    spec.hermes_tag,
                    spec.bytecode.instructions.len(),
                    spec.container.file_header.fields.len(),
                    spec.container.function_header.fields.len(),
                );
                if let Some(hermes_dec_root) = compare_hermes_dec {
                    let comparison = compare_against_hermes_dec(&spec, hermes_dec_root)?;
                    println!(
                        "compared against {}",
                        comparison.opcode_module_path.display()
                    );
                    if comparison.opcode_mismatches.is_empty()
                        && comparison.file_header_mismatches.is_empty()
                    {
                        println!("hermes-dec comparison: OK");
                    } else {
                        println!("hermes-dec comparison: mismatches found");
                        for mismatch in comparison.opcode_mismatches {
                            println!("opcode mismatch: {mismatch}");
                        }
                        for mismatch in comparison.file_header_mismatches {
                            println!("container mismatch: {mismatch}");
                        }
                    }
                }
            } else {
                for tag in extractor.list_tags()? {
                    println!("{tag}");
                }
            }
        }
    }

    Ok(())
}

fn detect_bytecode_version(bytes: &[u8]) -> anyhow::Result<u32> {
    if bytes.len() < 12 {
        bail!("input is too short to contain a Hermes file header");
    }

    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[8..12]);
    Ok(u32::from_le_bytes(buf))
}

fn render_raw_module(
    input: &PathBuf,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
    spec: &mercury_spec::HermesSpec,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# mercury decode");
    let _ = writeln!(out, "input {}", input.display());
    let _ = writeln!(out, "bytecode_version {}", raw.version);
    let _ = writeln!(out, "function_count {}", raw.function_count);
    let _ = writeln!(out, "function_bodies_start {}", raw.sections.function_bodies_start);
    let _ = writeln!(out);

    for function in &raw.functions {
        let function_name = render_function_name(function, raw, container);
        let labels = collect_labels(function, spec);
        let _ = writeln!(
            out,
            ".function {} name={} offset={} size={} params={} frame={} env={} read_cache={} write_cache={} flags=strict:{} exception:{} debug:{} overflow:{} prohibit:{}",
            function.function_index,
            function_name,
            function.offset,
            function.bytecode_size_in_bytes,
            function.param_count,
            function.frame_size,
            function.environment_size,
            function.highest_read_cache_index,
            function.highest_write_cache_index,
            function.flags.strict_mode,
            function.flags.has_exception_handler,
            function.flags.has_debug_info,
            function.flags.overflowed,
            function.flags.prohibit_invoke,
        );

        for instruction in &function.instructions {
            if let Some(label) = labels.get(&instruction.offset) {
                let _ = writeln!(out, "{label}:");
            }
            let _ = writeln!(
                out,
                "  {:04x}: {:<32} {}",
                instruction.offset,
                instruction.name,
                render_operands(function, instruction, raw, container, spec, &labels)
            );
        }

        let _ = writeln!(out, ".end");
        let _ = writeln!(out);
    }

    out
}

fn render_semantic_module(
    input: &PathBuf,
    semantic: &SemanticModule,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# mercury decode");
    let _ = writeln!(out, "input {}", input.display());
    let _ = writeln!(out, "bytecode_version {}", semantic.version);
    let _ = writeln!(out, "view semantic");
    let _ = writeln!(out, "function_count {}", semantic.functions.len());
    let _ = writeln!(out);

    let used_strings = collect_used_semantic_strings(semantic);
    if !used_strings.is_empty() {
        let _ = writeln!(out, ".strings");
        for string_id in used_strings {
            let rendered = resolve_string(string_id, container)
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| format!("<missing:{string_id}>"));
            let _ = writeln!(out, "  s{string_id} = {rendered}");
        }
        let _ = writeln!(out, ".end");
        let _ = writeln!(out);
    }

    for function in &semantic.functions {
        let raw_function = &raw.functions[function.function_index];
        let function_name = render_function_name(raw_function, raw, container);
        let labels = collect_semantic_labels(function);
        let _ = writeln!(
            out,
            ".function {} name={} params={} frame={} env={}",
            function.function_index,
            function_name,
            function.param_count,
            function.frame_size,
            function.environment_size,
        );

        for instruction in &function.instructions {
            if let Some(label) = labels.get(&instruction.offset) {
                let _ = writeln!(out, "{label}:");
            }
            let _ = writeln!(
                out,
                "  {:04x}: {}",
                instruction.offset,
                render_semantic_instruction(instruction, &labels, raw, container)
            );
        }

        let _ = writeln!(out, ".end");
        let _ = writeln!(out);
    }

    out
}

fn collect_labels(
    function: &RawFunction,
    spec: &mercury_spec::HermesSpec,
) -> std::collections::BTreeMap<u32, String> {
    let mut labels = std::collections::BTreeMap::new();
    let mut next_index = 1usize;

    for instruction in &function.instructions {
        let Some(instr_spec) = spec
            .bytecode
            .instructions
            .iter()
            .find(|candidate| candidate.opcode == instruction.opcode)
        else {
            continue;
        };

        for (operand, operand_spec) in instruction.operands.iter().zip(instr_spec.operands.iter()) {
            let Some(target) = branch_target(instruction.offset, operand, &operand_spec.kind) else {
                continue;
            };
            labels.entry(target).or_insert_with(|| {
                let label = format!("L{next_index}");
                next_index += 1;
                label
            });
        }
    }

    labels
}

fn collect_semantic_labels(function: &SemanticFunction) -> std::collections::BTreeMap<u32, String> {
    let mut labels = std::collections::BTreeMap::new();
    let mut next_index = 1usize;

    for instruction in &function.instructions {
        if let SemanticOp::Branch { target, .. } = instruction.op {
            labels.entry(target).or_insert_with(|| {
                let label = format!("L{next_index}");
                next_index += 1;
                label
            });
        }
    }

    labels
}

fn collect_used_semantic_strings(semantic: &SemanticModule) -> std::collections::BTreeSet<u32> {
    let mut strings = std::collections::BTreeSet::new();

    for function in &semantic.functions {
        for instruction in &function.instructions {
            match &instruction.op {
                SemanticOp::DeclareGlobalVar { name } => {
                    strings.insert(*name);
                }
                SemanticOp::LoadConstString { string, .. } => {
                    strings.insert(*string);
                }
                _ => {}
            }
        }
    }

    strings
}

fn render_semantic_instruction(
    instruction: &SemanticInstruction,
    labels: &std::collections::BTreeMap<u32, String>,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
) -> String {
    match &instruction.op {
        SemanticOp::CallBuiltin { dst, builtin, argc } => {
            format!("call_builtin {}, {builtin}, {argc}", render_register(*dst))
        }
        SemanticOp::CreateEnvironment { dst } => {
            format!("create_environment {}", render_register(*dst))
        }
        SemanticOp::DeclareGlobalVar { name } => {
            format!("declare_global_var {}", render_string_ref(*name, container))
        }
        SemanticOp::DeletePropertyById { dst, object, key } => format!(
            "delete_property_by_id {}, {}, {}",
            render_register(*dst),
            render_register(*object),
            render_string_ref(*key, container)
        ),
        SemanticOp::DeletePropertyByValue { dst, object, key } => format!(
            "delete_property_by_value {}, {}, {}",
            render_register(*dst),
            render_register(*object),
            render_semantic_value(key)
        ),
        SemanticOp::DirectEval {
            dst,
            callee,
            argument,
        } => format!(
            "direct_eval {}, {}, {}",
            render_register(*dst),
            render_register(*callee),
            render_semantic_value(argument)
        ),
        SemanticOp::GetEnvironment { dst, level } => {
            format!("get_environment {}, {level}", render_register(*dst))
        }
        SemanticOp::GetGlobalObject { dst } => {
            format!("get_global_object {}", render_register(*dst))
        }
        SemanticOp::GetNewTarget { dst } => {
            format!("get_new_target {}", render_register(*dst))
        }
        SemanticOp::LoadParam { dst, index } => {
            format!("load_param {}, {index}", render_register(*dst))
        }
        SemanticOp::LoadFromEnvironment {
            dst,
            environment,
            slot,
        } => {
            format!(
                "load_from_environment {}, {}, {slot}",
                render_register(*dst),
                render_register(*environment)
            )
        }
        SemanticOp::LoadImmediate { dst, value } => {
            format!(
                "load_immediate {}, {}",
                render_register(*dst),
                render_immediate(*value)
            )
        }
        SemanticOp::Branch { kind, target, args } => {
            let mnemonic = match kind {
                BranchKind::Jump => "branch",
                BranchKind::JumpFalse => "branch_false",
                BranchKind::JumpTrue => "branch_true",
                BranchKind::JumpUndefined => "branch_undefined",
                BranchKind::Greater => "branch_greater",
                BranchKind::GreaterEqual => "branch_greater_equal",
                BranchKind::NotGreater => "branch_not_greater",
                BranchKind::NotGreaterEqual => "branch_not_greater_equal",
                BranchKind::Less => "branch_less",
                BranchKind::LessEqual => "branch_less_equal",
                BranchKind::NotLess => "branch_not_less",
                BranchKind::NotLessEqual => "branch_not_less_equal",
                BranchKind::Equal => "branch_equal",
                BranchKind::NotEqual => "branch_not_equal",
                BranchKind::StrictEqual => "branch_strict_equal",
                BranchKind::StrictNotEqual => "branch_strict_not_equal",
                BranchKind::RawConditional => "branch_raw",
            };
            let label = labels
                .get(target)
                .cloned()
                .unwrap_or_else(|| format!("L?_{target:04x}"));
            if args.is_empty() {
                format!("{mnemonic} {label}")
            } else {
                format!(
                    "{mnemonic} {}, {label}",
                    args.iter()
                        .map(render_semantic_value)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
        SemanticOp::CreateClosure {
            kind,
            dst,
            environment,
            function,
        } => {
            let mnemonic = match kind {
                mercury_ir::ClosureKind::Normal => "create_closure",
                mercury_ir::ClosureKind::Generator => "create_generator_closure",
                mercury_ir::ClosureKind::Async => "create_async_closure",
            };
            format!(
                "{mnemonic} {}, {}, {}",
                render_register(*dst),
                render_register(*environment),
                render_function_ref(*function, raw, container),
            )
        }
        SemanticOp::Construct {
            dst,
            callee,
            argument_count,
        } => format!(
            "construct {}, {}, {}",
            render_register(*dst),
            render_register(*callee),
            render_semantic_value(argument_count)
        ),
        SemanticOp::CreateGenerator {
            dst,
            environment,
            function,
        } => format!(
            "create_generator {}, {}, {}",
            render_register(*dst),
            render_register(*environment),
            render_function_ref(*function, raw, container)
        ),
        SemanticOp::CreateRegExp {
            dst,
            pattern_id,
            flags_id,
            regexp_id,
        } => format!(
            "create_reg_exp {}, {pattern_id}, {flags_id}, {regexp_id}",
            render_register(*dst)
        ),
        SemanticOp::CreateThis {
            dst,
            callee,
            new_target,
        } => format!(
            "create_this {}, {}, {}",
            render_register(*dst),
            render_register(*callee),
            render_semantic_value(new_target)
        ),
        SemanticOp::LoadConstString { dst, string } => {
            format!(
                "load_const_string {}, {}",
                render_register(*dst),
                render_string_ref(*string, container)
            )
        }
        SemanticOp::LoadThisNS { dst } => format!("load_this_ns {}", render_register(*dst)),
        SemanticOp::Move { dst, src } => {
            format!("move {}, {}", render_register(*dst), render_semantic_value(src))
        }
        SemanticOp::NewArray { dst } => format!("new_array {}", render_register(*dst)),
        SemanticOp::NewArrayWithBuffer {
            dst,
            min_size,
            max_size,
            buffer_index,
        } => format!(
            "new_array_with_buffer {}, {min_size}, {max_size}, {buffer_index}",
            render_register(*dst)
        ),
        SemanticOp::NewObject { dst } => format!("new_object {}", render_register(*dst)),
        SemanticOp::NewObjectWithBuffer {
            dst,
            key_count,
            value_count,
            key_buffer_index,
            value_buffer_index,
        } => format!(
            "new_object_with_buffer {}, {key_count}, {value_count}, {key_buffer_index}, {value_buffer_index}",
            render_register(*dst)
        ),
        SemanticOp::Binary { kind, dst, lhs, rhs } => {
            let mnemonic = match kind {
                BinaryOpKind::Add => "add",
                BinaryOpKind::AddN => "add_n",
                BinaryOpKind::BitAnd => "bit_and",
                BinaryOpKind::BitOr => "bit_or",
                BinaryOpKind::BitXor => "bit_xor",
                BinaryOpKind::Sub => "sub",
                BinaryOpKind::SubN => "sub_n",
                BinaryOpKind::Mul => "mul",
                BinaryOpKind::MulN => "mul_n",
                BinaryOpKind::Div => "div",
                BinaryOpKind::DivN => "div_n",
                BinaryOpKind::Eq => "eq",
                BinaryOpKind::IsIn => "is_in",
                BinaryOpKind::LShift => "lshift",
                BinaryOpKind::Mod => "mod",
                BinaryOpKind::Neq => "neq",
                BinaryOpKind::RShift => "rshift",
                BinaryOpKind::StrictEq => "strict_eq",
                BinaryOpKind::StrictNeq => "strict_neq",
                BinaryOpKind::Greater => "greater",
                BinaryOpKind::GreaterEqual => "greater_eq",
                BinaryOpKind::InstanceOf => "instance_of",
                BinaryOpKind::Less => "less",
                BinaryOpKind::LessEqual => "less_eq",
                BinaryOpKind::SelectObject => "select_object",
                BinaryOpKind::URShift => "urshift",
            };
            format!(
                "{mnemonic} {}, {}, {}",
                render_register(*dst),
                render_semantic_value(lhs),
                render_semantic_value(rhs)
            )
        }
        SemanticOp::Unary { kind, dst, operand } => {
            let mnemonic = match kind {
                UnaryOpKind::AddEmptyString => "add_empty_string",
                UnaryOpKind::BitNot => "bit_not",
                UnaryOpKind::Dec => "dec",
                UnaryOpKind::Not => "not",
                UnaryOpKind::Negate => "negate",
                UnaryOpKind::ToInt32 => "to_int32",
                UnaryOpKind::ToNumber => "to_number",
                UnaryOpKind::ToNumeric => "to_numeric",
                UnaryOpKind::TypeOf => "type_of",
            };
            format!(
                "{mnemonic} {}, {}",
                render_register(*dst),
                render_semantic_value(operand)
            )
        }
        SemanticOp::PropertyGet {
            kind,
            dst,
            object,
            cache_index,
            key,
        } => {
            let mnemonic = match kind {
                PropertyAccessKind::ById => "get_by_id",
                PropertyAccessKind::ByIdShort => "get_by_id_short",
                PropertyAccessKind::ByIdLong => "get_by_id_long",
                PropertyAccessKind::TryById => "try_get_by_id",
                PropertyAccessKind::TryByIdLong => "try_get_by_id_long",
            };
            format!(
                "{mnemonic} {}, {}, {}, {}",
                render_register(*dst),
                render_register(*object),
                cache_index,
                render_string_ref(*key, container)
            )
        }
        SemanticOp::PropertyGetByValue { dst, object, key } => {
            format!(
                "get_by_value {}, {}, {}",
                render_register(*dst),
                render_register(*object),
                render_semantic_value(key)
            )
        }
        SemanticOp::PropertyPut {
            kind,
            object,
            value,
            cache_index,
            key,
        } => {
            let mnemonic = match kind {
                PropertyAccessKind::ById => "put_by_id",
                PropertyAccessKind::ByIdShort => "put_by_id_short",
                PropertyAccessKind::ByIdLong => "put_by_id_long",
                PropertyAccessKind::TryById => "put_try_by_id",
                PropertyAccessKind::TryByIdLong => "put_try_by_id_long",
            };
            format!(
                "{mnemonic} {}, {}, {}, {}",
                render_register(*object),
                render_semantic_value(value),
                cache_index,
                render_string_ref(*key, container)
            )
        }
        SemanticOp::PropertyPutByValue { object, key, value } => {
            format!(
                "put_by_value {}, {}, {}",
                render_register(*object),
                render_semantic_value(key),
                render_semantic_value(value)
            )
        }
        SemanticOp::PropertyPutOwnByValue {
            object,
            key,
            value,
            enumerable,
        } => format!(
            "put_own_by_value {}, {}, {}, {}",
            render_register(*object),
            render_semantic_value(key),
            render_semantic_value(value),
            render_semantic_value(enumerable)
        ),
        SemanticOp::PropertyPutOwnGetterSetterByValue {
            object,
            key,
            getter,
            setter,
            enumerable,
        } => format!(
            "put_own_getter_setter_by_value {}, {}, {}, {}, {}",
            render_register(*object),
            render_semantic_value(key),
            render_semantic_value(getter),
            render_semantic_value(setter),
            render_semantic_value(enumerable)
        ),
        SemanticOp::PropertyDefine {
            kind,
            object,
            value,
            key,
        } => {
            let mnemonic = match kind {
                PropertyDefineKind::NewOwnById => "put_new_own_by_id",
                PropertyDefineKind::NewOwnByIdShort => "put_new_own_by_id_short",
                PropertyDefineKind::NewOwnByIdLong => "put_new_own_by_id_long",
            };
            format!(
                "{mnemonic} {}, {}, {}",
                render_register(*object),
                render_semantic_value(value),
                render_string_ref(*key, container)
            )
        }
        SemanticOp::PropertyPutIndex { object, value, index } => {
            format!(
                "put_own_by_index {}, {}, {index}",
                render_register(*object),
                render_semantic_value(value)
            )
        }
        SemanticOp::Increment { dst, src } => {
            format!("increment {}, {}", render_register(*dst), render_semantic_value(src))
        }
        SemanticOp::Catch { dst } => format!("catch {}", render_register(*dst)),
        SemanticOp::CompleteGenerator => "complete_generator".to_owned(),
        SemanticOp::GetArgumentsLength { dst, arguments } => format!(
            "get_arguments_length {}, {}",
            render_register(*dst),
            render_register(*arguments)
        ),
        SemanticOp::GetArgumentsPropByValue {
            dst,
            arguments,
            key,
        } => format!(
            "get_arguments_prop_by_value {}, {}, {}",
            render_register(*dst),
            render_register(*arguments),
            render_semantic_value(key)
        ),
        SemanticOp::GetNextPName {
            dst,
            iterator,
            base,
            index,
            size,
        } => format!(
            "get_next_pname {}, {}, {}, {}, {}",
            render_register(*dst),
            render_register(*iterator),
            render_register(*base),
            render_register(*index),
            render_register(*size)
        ),
        SemanticOp::GetPNameList {
            dst,
            iterator,
            base,
            index,
        } => format!(
            "get_pname_list {}, {}, {}, {}",
            render_register(*dst),
            render_register(*iterator),
            render_register(*base),
            render_register(*index)
        ),
        SemanticOp::IteratorClose { iterator, value } => format!(
            "iterator_close {}, {}",
            render_register(*iterator),
            render_semantic_value(value)
        ),
        SemanticOp::IteratorBegin { dst, source } => format!(
            "iterator_begin {}, {}",
            render_register(*dst),
            render_register(*source)
        ),
        SemanticOp::IteratorNext {
            dst,
            iterator,
            source,
        } => format!(
            "iterator_next {}, {}, {}",
            render_register(*dst),
            render_register(*iterator),
            render_semantic_value(source)
        ),
        SemanticOp::NewObjectWithParent { dst, parent } => format!(
            "new_object_with_parent {}, {}",
            render_register(*dst),
            render_register(*parent)
        ),
        SemanticOp::ReifyArguments { dst } => {
            format!("reify_arguments {}", render_register(*dst))
        }
        SemanticOp::ResumeGenerator { dst, value } => format!(
            "resume_generator {}, {}",
            render_register(*dst),
            render_semantic_value(value)
        ),
        SemanticOp::SaveGenerator { value } => {
            format!("save_generator {}", render_semantic_value(value))
        }
        SemanticOp::StartGenerator => "start_generator".to_owned(),
        SemanticOp::StoreToEnvironment {
            environment,
            value,
            slot,
        } => {
            format!(
                "store_to_environment {}, {}, {slot}",
                render_register(*environment),
                render_semantic_value(value)
            )
        }
        SemanticOp::SwitchImm {
            input,
            table_offset,
            default_offset,
            min_case,
            max_case,
        } => format!(
            "switch_imm {}, {table_offset}, {default_offset}, {min_case}, {max_case}",
            render_semantic_value(input)
        ),
        SemanticOp::Call {
            dst,
            callee,
            this_arg,
            args,
        } => {
            let mut parts = vec![render_register(*dst), render_register(*callee)];
            if let Some(this_arg) = this_arg {
                parts.push(render_register(*this_arg));
            }
            parts.extend(args.iter().map(render_semantic_value));
            format!("call {}", parts.join(", "))
        }
        SemanticOp::Return { value } => format!("return {}", render_semantic_value(value)),
        SemanticOp::Throw { value } => format!("throw {}", render_semantic_value(value)),
        SemanticOp::Raw { mnemonic, operands } => {
            let mnemonic = camel_to_snake_case(mnemonic);
            if operands.is_empty() {
                mnemonic
            } else {
                format!(
                    "{} {}",
                    mnemonic,
                    operands
                        .iter()
                        .map(render_semantic_value)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

fn render_semantic_value(value: &Value) -> String {
    match value {
        Value::Register(register) => render_register(*register),
        Value::U32(value) => value.to_string(),
        Value::I32(value) => value.to_string(),
        Value::F64(value) => value.to_string(),
    }
}

fn render_register(register: mercury_ir::Register) -> String {
    format!("r{}", register.0)
}

fn render_immediate(value: Immediate) -> String {
    match value {
        Immediate::Undefined => "undefined".to_owned(),
        Immediate::Null => "null".to_owned(),
        Immediate::Bool(value) => value.to_string(),
        Immediate::U32(value) => value.to_string(),
        Immediate::I32(value) => value.to_string(),
        Immediate::F64(value) => value.to_string(),
    }
}

fn render_string_ref(string_id: u32, container: &mercury_binary::HbcContainer) -> String {
    resolve_string(string_id, container)
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| format!("s{string_id}"))
}

fn render_function_ref(
    function_id: u32,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
) -> String {
    let Some(function) = raw.functions.get(function_id as usize) else {
        return format!("fn{function_id}");
    };
    let name = render_function_name(function, raw, container);
    format!("@{}", name.trim_matches('"'))
}

fn camel_to_snake_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    let mut prev_was_lower_or_digit = false;

    for ch in value.chars() {
        if ch.is_ascii_uppercase() {
            if prev_was_lower_or_digit {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_was_lower_or_digit = false;
        } else {
            prev_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
            out.push(ch.to_ascii_lowercase());
        }
    }

    out
}

fn branch_target(offset: u32, operand: &RawOperand, kind: &str) -> Option<u32> {
    match (kind, operand) {
        ("Addr8", RawOperand::I8(value)) => Some(offset.wrapping_add_signed(*value as i32)),
        ("Addr32", RawOperand::I32(value)) => Some(offset.wrapping_add_signed(*value)),
        _ => None,
    }
}

fn render_operands(
    _function: &RawFunction,
    instruction: &RawInstruction,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
    spec: &mercury_spec::HermesSpec,
    labels: &std::collections::BTreeMap<u32, String>,
) -> String {
    let Some(instr_spec) = spec
        .bytecode
        .instructions
        .iter()
        .find(|candidate| candidate.opcode == instruction.opcode)
    else {
        return render_fallback_operands(&instruction.operands);
    };

    instruction
        .operands
        .iter()
        .zip(instr_spec.operands.iter())
        .map(|(operand, operand_spec)| {
            render_operand(
                _function,
                instruction,
                operand,
                operand_spec,
                raw,
                container,
                labels,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_operand(
    _function: &RawFunction,
    instruction: &RawInstruction,
    operand: &RawOperand,
    operand_spec: &mercury_spec::InstructionOperandSpec,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
    labels: &std::collections::BTreeMap<u32, String>,
) -> String {
    if let Some(target) = branch_target(instruction.offset, operand, &operand_spec.kind) {
        if let Some(label) = labels.get(&target) {
            return label.clone();
        }
    }

    match operand_spec.kind.as_str() {
        "Reg8" => match operand {
            RawOperand::U8(value) => format!("r{value}"),
            _ => render_raw_operand(operand),
        },
        "Reg32" => match operand {
            RawOperand::U32(value) => format!("r{value}"),
            _ => render_raw_operand(operand),
        },
        _ => match operand_spec.meaning {
            Some(mercury_spec::OperandMeaning::StringId) => resolve_string_operand(operand, container),
            Some(mercury_spec::OperandMeaning::FunctionId) => resolve_function_operand(operand, raw, container),
            _ => render_raw_operand(operand),
        },
    }
}

fn render_fallback_operands(operands: &[RawOperand]) -> String {
    operands
        .iter()
        .map(render_raw_operand)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_raw_operand(operand: &RawOperand) -> String {
    match operand {
        RawOperand::U8(value) => value.to_string(),
        RawOperand::U16(value) => value.to_string(),
        RawOperand::U32(value) => value.to_string(),
        RawOperand::I8(value) => value.to_string(),
        RawOperand::I32(value) => value.to_string(),
        RawOperand::F64(value) => value.to_string(),
    }
}

fn render_function_name(
    function: &RawFunction,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
) -> String {
    if function.function_index == 0 {
        return "global".to_owned();
    }

    let Some(header) = container.function_headers.get(function.function_index) else {
        return format!("function_{}", function.function_index);
    };

    if let Some(name) = resolve_string(header.function_name, container) {
        if !name.is_empty() {
            return format!("{name:?}");
        }
    }

    let _ = raw;
    format!("function_{}", function.function_index)
}

fn resolve_string_operand(
    operand: &RawOperand,
    container: &mercury_binary::HbcContainer,
) -> String {
    let Some(string_id) = raw_u32_value(operand) else {
        return render_raw_operand(operand);
    };

    resolve_string(string_id, container)
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| string_id.to_string())
}

fn resolve_function_operand(
    operand: &RawOperand,
    raw: &mercury_ir::RawModule,
    container: &mercury_binary::HbcContainer,
) -> String {
    let Some(function_id) = raw_u32_value(operand) else {
        return render_raw_operand(operand);
    };

    let Some(function) = raw.functions.get(function_id as usize) else {
        return function_id.to_string();
    };
    format!("Function<{}>", render_function_name(function, raw, container).trim_matches('"'))
}

fn raw_u32_value(operand: &RawOperand) -> Option<u32> {
    match operand {
        RawOperand::U8(value) => Some(*value as u32),
        RawOperand::U16(value) => Some(*value as u32),
        RawOperand::U32(value) => Some(*value),
        _ => None,
    }
}

fn resolve_string(string_id: u32, container: &mercury_binary::HbcContainer) -> Option<String> {
    let entry = container.small_string_table_entries.get(string_id as usize)?;
    let (offset, length) = if entry.is_overflowed {
        let overflow = container
            .overflow_string_table_entries
            .get(entry.offset as usize)?;
        (overflow.offset as usize, overflow.length as usize)
    } else {
        (entry.offset as usize, entry.length as usize)
    };

    if entry.is_utf16 {
        let byte_len = length.checked_mul(2)?;
        let slice = container.string_storage.get(offset..offset + byte_len)?;
        let words = slice
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        Some(String::from_utf16_lossy(&words))
    } else {
        let slice = container.string_storage.get(offset..offset + length)?;
        Some(String::from_utf8_lossy(slice).into_owned())
    }
}

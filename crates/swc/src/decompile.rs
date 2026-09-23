use crate::{Error, SwcModule, ast_builder as b, cfg, literal};
use mercury_binary::{HbcContainer, decode_raw_module, parse_hbc_container_with_spec};
use mercury_ir::{RawFunction, RawInstruction, RawModule, RawOperand};
use num_bigint::BigInt;
use std::collections::HashSet;
use swc_core::{
    common::DUMMY_SP,
    ecma::{
        ast::*,
        visit::{VisitMut, VisitMutWith},
    },
};

/// Decompile the supported HBC-96 subset into executable SWC nodes. Temporaries
/// and a block dispatcher preserve evaluation order; this is not source recovery.
/// Generated calls use the standard Reflect.apply intrinsic (see README).
pub fn decompile(bytes: &[u8]) -> Result<SwcModule, Error> {
    let version = bytes
        .get(8..12)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .ok_or_else(|| Error::Bytecode("missing header".into()))?;
    if version != 96 {
        return Err(Error::Version {
            expected: 96,
            actual: version,
        });
    }
    let spec = mercury_spec_builtin::load_spec(version)
        .ok_or_else(|| Error::Bytecode("missing spec".into()))?;
    let container = parse_hbc_container_with_spec(bytes, &spec.container)
        .map_err(|e| Error::Bytecode(e.to_string()))?;
    let h = &container.header;
    if h.options.raw != 0
        || h.cjs_module_count != 0
        || h.segment_id != 0
        || h.num_string_switch_imms != 0
    {
        return Err(Error::Unsupported(
            "bytecode options, modules or string-switch tables".into(),
        ));
    }
    let raw = decode_raw_module(&container, bytes, &spec.bytecode)
        .map_err(|e| Error::Bytecode(e.to_string()))?;
    if h.global_code_index as usize >= raw.functions.len() {
        return Err(Error::Bytecode("invalid entry function".into()));
    }
    let lower = Lower {
        container: &container,
        raw: &raw,
    };
    let needs_define = raw
        .functions
        .iter()
        .flat_map(|function| &function.instructions)
        .any(|op| is_define_own(&op.name));
    let needs_regexp = has_opcode(&raw, "CreateRegExp");
    let needs_bigint = raw.functions.iter().any(|function| {
        function.instructions.iter().any(|op| {
            matches!(
                op.name.as_str(),
                "LoadConstBigInt" | "LoadConstBigIntLongIndex"
            )
        })
    });
    let mut globals = Vec::new();
    let mut seen_globals = HashSet::new();
    let names = container
        .function_headers
        .iter()
        .map(|header| lower.string(header.function_name))
        .collect::<Result<Vec<_>, _>>()?;
    let mut prefix = "_mercury".to_owned();
    while names.iter().any(|name| name.starts_with(&prefix)) {
        prefix.push('_');
    }
    let mut factories = Vec::new();
    for f in &raw.functions {
        if f.frame_size > 65_536 {
            return Err(Error::Unsupported(
                "decompiler register budget exceeded".into(),
            ));
        }
        if f.flags.prohibit_invoke != 2 {
            return Err(Error::Unsupported(format!(
                "function {}: invocation flags",
                f.function_index
            )));
        }
        for op in &f.instructions {
            if op.name == "DeclareGlobalVar" {
                let name = lower.string(uint(op, 0)?)?;
                if !valid_name(&name) {
                    return Err(unsupported(
                        f,
                        op,
                        "global name is not a supported identifier",
                    ));
                }
                if f.function_index != h.global_code_index as usize {
                    return Err(unsupported(
                        f,
                        op,
                        "global declaration outside the entry function",
                    ));
                }
                if seen_globals.insert(name.clone()) {
                    globals.push(name);
                }
            }
        }
        let name = lower.string(container.function_headers[f.function_index].function_name)?;
        if !name.is_empty() && !valid_name(&name) {
            return Err(Error::Unsupported(format!("function name {name:?}")));
        }
        let params = (1..f.param_count).map(|i| format!("_a{i}")).collect();
        let function = b::function(
            if name.is_empty() { None } else { Some(&name) },
            params,
            lower.function(f)?,
        );
        factories.push(b::var(
            &format!("_make{}", f.function_index),
            Some(b::function(
                None,
                vec!["_env".into()],
                vec![b::ret(function)],
            )),
        ));
    }
    // Global var declarations stay at script scope, retaining global binding
    // behaviour. Everything introduced by the decompiler lives inside the IIFE.
    let mut body: Vec<_> = globals.iter().map(|name| b::var(name, None)).collect();
    factories.push(b::ret(b::call(
        b::id("_apply"),
        vec![
            b::call(b::id(&format!("_make{}", h.global_code_index)), vec![]),
            b::id("_g"),
            b::array(vec![]),
        ],
    )));
    let mut wrapper_params = vec!["_g".into(), "_apply".into()];
    let mut wrapper_args = vec![
        b::this(),
        b::member(
            b::member(b::this(), b::string("Reflect")),
            b::string("apply"),
        ),
    ];
    if needs_define {
        wrapper_params.push("_define".into());
        wrapper_args.push(b::member(
            b::member(b::this(), b::string("Reflect")),
            b::string("defineProperty"),
        ));
    }
    if needs_regexp {
        wrapper_params.push("_regexp".into());
        wrapper_args.push(b::member(b::this(), b::string("RegExp")));
    }
    if needs_bigint {
        wrapper_params.push("_bigint".into());
        wrapper_args.push(b::member(b::this(), b::string("BigInt")));
    }
    let mut wrapper = b::function(None, wrapper_params, factories);
    wrapper.visit_mut_with(&mut Namespace(prefix));
    body.push(b::expr(b::call(wrapper, wrapper_args)));
    Ok(SwcModule::generated(Program::Script(Script {
        span: DUMMY_SP,
        body,
        shebang: None,
    })))
}

// Keep generated local names distinct from named function-expression bindings.
// Otherwise a source function named `_g` could capture our global-object helper.
struct Namespace(String);
impl VisitMut for Namespace {
    fn visit_mut_ident(&mut self, ident: &mut Ident) {
        if ident.sym != *"arguments" {
            ident.sym = format!("{}{}", self.0, ident.sym).into();
        }
    }
    fn visit_mut_fn_expr(&mut self, expr: &mut FnExpr) {
        // The original function name is observable; only rename its internals.
        expr.function.visit_mut_with(self);
    }
}

struct Lower<'a> {
    container: &'a HbcContainer,
    raw: &'a RawModule,
}
impl Lower<'_> {
    fn string(&self, id: u32) -> Result<String, Error> {
        let error = || Error::Bytecode(format!("invalid string {id}"));
        let entry = self
            .container
            .small_string_table_entries
            .get(id as usize)
            .ok_or_else(error)?;
        let (offset, len) = if entry.is_overflowed {
            let entry = self
                .container
                .overflow_string_table_entries
                .get(entry.offset as usize)
                .ok_or_else(error)?;
            (entry.offset as usize, entry.length as usize)
        } else {
            (entry.offset as usize, entry.length as usize)
        };
        let end = offset
            .checked_add(
                len.checked_mul(if entry.is_utf16 { 2 } else { 1 })
                    .ok_or_else(error)?,
            )
            .ok_or_else(error)?;
        let data = self
            .container
            .string_storage
            .get(offset..end)
            .ok_or_else(error)?;
        if entry.is_utf16 {
            String::from_utf16(
                &data
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| Error::Unsupported("unpaired UTF-16 surrogate".into()))
        } else {
            String::from_utf8(data.to_vec()).map_err(|_| error())
        }
    }
    fn function(&self, f: &RawFunction) -> Result<Vec<Stmt>, Error> {
        let mut body = Vec::new();
        if f.flags.strict_mode {
            body.push(b::expr(b::string("use strict")));
        }
        for r in 0..f.frame_size {
            body.push(b::var(&format!("_r{r}"), None));
        }
        if f.instructions.iter().any(|op| is_define_own(&op.name)) {
            body.push(b::var("_desc", None));
        }
        if !f.exception_handlers.is_empty() {
            body.push(b::var("_thrown", None));
        }
        body.push(b::var("_pc", Some(b::number(0.0))));
        let mut cases = Vec::new();
        for block in cfg::blocks(f)? {
            let mut stmts = Vec::new();
            let mut terminated = false;
            for op in block.instructions {
                if op.name == "SwitchImm" {
                    let table = f
                        .switch_tables
                        .iter()
                        .find(|table| table.instruction_offset == op.offset)
                        .ok_or_else(|| unsupported(f, op, "missing switch table"))?;
                    let mut switch_cases = table
                        .displacements
                        .iter()
                        .enumerate()
                        .map(|(index, displacement)| {
                            let value = table.min_case.checked_add(index as u32).ok_or_else(|| {
                                unsupported(f, op, "switch case value overflows")
                            })?;
                            Ok(SwitchCase {
                                span: DUMMY_SP,
                                test: Some(b::number(f64::from(value))),
                                cons: vec![
                                    set_pc(cfg::switch_target(op.offset, *displacement)?),
                                    Stmt::Break(BreakStmt {
                                        span: DUMMY_SP,
                                        label: None,
                                    }),
                                ],
                            })
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    switch_cases.push(SwitchCase {
                        span: DUMMY_SP,
                        test: None,
                        cons: vec![set_pc(cfg::relative_target(op, 2)?)],
                    });
                    stmts.push(Stmt::Switch(SwitchStmt {
                        span: DUMMY_SP,
                        discriminant: register(f, op, 0)?,
                        cases: switch_cases,
                    }));
                    stmts.push(Stmt::Continue(ContinueStmt {
                        span: DUMMY_SP,
                        label: None,
                    }));
                    terminated = true;
                } else if op.name.starts_with('J') {
                    let target = cfg::target(op)?;
                    let name = op.name.strip_suffix("Long").unwrap_or(&op.name);
                    if name == "Jmp" {
                        stmts.push(set_pc(target));
                    } else {
                        let next = block
                            .next
                            .ok_or_else(|| unsupported(f, op, "conditional has no fallthrough"))?;
                        stmts.push(Stmt::If(IfStmt {
                            span: DUMMY_SP,
                            test: branch_condition(f, op)?,
                            cons: Box::new(set_pc(target)),
                            alt: Some(Box::new(set_pc(next))),
                        }));
                    }
                    stmts.push(Stmt::Continue(ContinueStmt {
                        span: DUMMY_SP,
                        label: None,
                    }));
                    terminated = true;
                } else {
                    stmts.extend(self.instruction(f, op)?);
                    terminated = matches!(op.name.as_str(), "Ret" | "Throw");
                }
            }
            if !terminated {
                let next = block.next.ok_or_else(|| {
                    Error::Bytecode(format!("function {} falls off its end", f.function_index))
                })?;
                stmts.push(set_pc(next));
                stmts.push(Stmt::Continue(ContinueStmt {
                    span: DUMMY_SP,
                    label: None,
                }));
            }
            cases.push(SwitchCase {
                span: DUMMY_SP,
                test: Some(b::number(f64::from(block.start))),
                cons: stmts,
            });
        }
        let dispatch = Stmt::Switch(SwitchStmt {
            span: DUMMY_SP,
            discriminant: b::id("_pc"),
            cases,
        });
        let loop_body = if f.exception_handlers.is_empty() {
            vec![dispatch]
        } else {
            let mut catch_body = Vec::new();
            for handler in &f.exception_handlers {
                catch_body.push(Stmt::If(IfStmt {
                    span: DUMMY_SP,
                    test: b::binary(
                        BinaryOp::LogicalAnd,
                        b::binary(
                            BinaryOp::LtEq,
                            b::number(f64::from(handler.start)),
                            b::id("_pc"),
                        ),
                        b::binary(
                            BinaryOp::Lt,
                            b::id("_pc"),
                            b::number(f64::from(handler.end)),
                        ),
                    ),
                    cons: Box::new(Stmt::Block(b::block(vec![
                        b::assign(b::id("_thrown"), b::id("_caught")),
                        set_pc(handler.target),
                        Stmt::Continue(ContinueStmt {
                            span: DUMMY_SP,
                            label: None,
                        }),
                    ]))),
                    alt: None,
                }));
            }
            catch_body.push(Stmt::Throw(ThrowStmt {
                span: DUMMY_SP,
                arg: b::id("_caught"),
            }));
            vec![Stmt::Try(Box::new(TryStmt {
                span: DUMMY_SP,
                block: b::block(vec![dispatch]),
                handler: Some(CatchClause {
                    span: DUMMY_SP,
                    param: Some(Pat::Ident(b::ident("_caught").into())),
                    body: b::block(catch_body),
                }),
                finalizer: None,
            }))]
        };
        body.push(Stmt::While(WhileStmt {
            span: DUMMY_SP,
            test: b::boolean(true),
            body: Box::new(Stmt::Block(b::block(loop_body))),
        }));
        Ok(body)
    }
    fn instruction(&self, f: &RawFunction, op: &RawInstruction) -> Result<Vec<Stmt>, Error> {
        let r = |i| register(f, op, i);
        let value = match op.name.as_str() {
            "DeclareGlobalVar" => return Ok(vec![]),
            // Environment arrays store their parent at index 0 and bytecode
            // slots at index + 1. Passing the exact same array to each child
            // preserves shared mutation between sibling closures.
            "CreateEnvironment" => {
                let mut values = Vec::with_capacity(f.environment_size as usize + 1);
                values.push(b::id("_env"));
                values.extend((0..f.environment_size).map(|_| b::undefined()));
                b::array(values)
            }
            "CreateClosure" | "CreateClosureLongIndex" => {
                let target = uint(op, 2)?;
                if target as usize >= self.raw.functions.len() {
                    return Err(Error::Bytecode("invalid closure target".into()));
                }
                b::call(b::id(&format!("_make{target}")), vec![r(1)?])
            }
            "GetEnvironment" => {
                let mut environment = b::id("_env");
                for _ in 0..uint(op, 1)? {
                    environment = b::member(environment, b::number(0.0));
                }
                environment
            }
            "LoadFromEnvironment" | "LoadFromEnvironmentL" => {
                b::member(r(1)?, environment_slot(op, 2)?)
            }
            "StoreToEnvironment"
            | "StoreToEnvironmentL"
            | "StoreNPToEnvironment"
            | "StoreNPToEnvironmentL" => {
                return Ok(vec![b::assign(
                    b::member(r(0)?, environment_slot(op, 1)?),
                    r(2)?,
                )]);
            }
            "GetGlobalObject" => b::id("_g"),
            "LoadParam" | "LoadParamLong" => {
                let index = uint(op, 1)?;
                if index == 0 {
                    b::this()
                } else {
                    b::member(b::id("arguments"), b::number(f64::from(index - 1)))
                }
            }
            "LoadThisNS" => b::this(),
            "LoadConstZero" => b::number(0.0),
            "LoadConstUInt8" => b::number(f64::from(uint(op, 1)?)),
            "LoadConstInt" => match op.operands.get(1) {
                Some(RawOperand::I32(v)) => b::number(f64::from(*v)),
                _ => return Err(Error::Bytecode("invalid integer".into())),
            },
            "LoadConstDouble" => match op.operands.get(1) {
                Some(RawOperand::F64(v)) if v.is_finite() => b::number(*v),
                _ => return Err(unsupported(f, op, "non-finite double")),
            },
            "LoadConstBigInt" | "LoadConstBigIntLongIndex" => {
                b::call(b::id("_bigint"), vec![b::string(&self.big_int(uint(op, 1)?)?)])
            }
            "LoadConstTrue" => b::boolean(true),
            "LoadConstFalse" => b::boolean(false),
            "LoadConstUndefined" => b::undefined(),
            "LoadConstNull" => b::null(),
            "LoadConstString" | "LoadConstStringLongIndex" => {
                b::string(&self.string(uint(op, 1)?)?)
            }
            "CreateRegExp" => {
                let regexp_id = uint(op, 3)? as usize;
                if regexp_id >= self.container.reg_exp_entries.len() {
                    return Err(unsupported(f, op, "invalid regexp table index"));
                }
                b::new(
                    b::id("_regexp"),
                    vec![
                        b::string(&self.string(uint(op, 1)?)?),
                        b::string(&self.string(uint(op, 2)?)?),
                    ],
                )
            }
            "Mov" | "MovLong" => r(1)?,
            "Catch" => b::id("_thrown"),
            "Ret" => return Ok(vec![b::ret(r(0)?)]),
            "Throw" => {
                return Ok(vec![Stmt::Throw(ThrowStmt {
                    span: DUMMY_SP,
                    arg: r(0)?,
                })]);
            }
            "PutById" | "PutByIdLong" => {
                return Ok(vec![b::assign(
                    b::member(r(0)?, b::string(&self.string(uint(op, 3)?)?)),
                    r(1)?,
                )]);
            }
            "GetById" | "GetByIdShort" | "GetByIdLong" | "TryGetById" | "TryGetByIdLong" => {
                let key = self.string(uint(op, 3)?)?;
                let value = b::member(r(1)?, b::string(&key));
                if op.name.starts_with("Try") {
                    return Ok(vec![
                        Stmt::If(IfStmt {
                            span: DUMMY_SP,
                            test: b::unary(
                                UnaryOp::Bang,
                                b::binary(BinaryOp::In, b::string(&key), r(1)?),
                            ),
                            cons: Box::new(Stmt::Throw(ThrowStmt {
                                span: DUMMY_SP,
                                arg: Box::new(Expr::New(NewExpr {
                                    span: DUMMY_SP,
                                    ctxt: Default::default(),
                                    callee: b::member(b::id("_g"), b::string("ReferenceError")),
                                    args: Some(vec![ExprOrSpread {
                                        spread: None,
                                        expr: b::string(&format!("{key} is not defined")),
                                    }]),
                                    type_args: None,
                                })),
                            })),
                            alt: None,
                        }),
                        b::assign(r(0)?, value),
                    ]);
                }
                value
            }
            "GetByVal" => b::member(r(1)?, r(2)?),
            "PutByVal" => return Ok(vec![b::assign(b::member(r(0)?, r(1)?), r(2)?)]),
            "Call1" | "Call2" | "Call3" | "Call4" => {
                let args = (3..op.operands.len())
                    .map(r)
                    .collect::<Result<Vec<_>, _>>()?;
                b::call(b::id("_apply"), vec![r(1)?, r(2)?, b::array(args)])
            }
            "Call" | "CallLong" => {
                let argument_count = uint(op, 2)?;
                if argument_count == 0 {
                    return Err(unsupported(f, op, "call has no this argument"));
                }
                // HBC 96 reserves six VM registers after the reverse-ordered
                // argument area at the end of the frame.
                const CALL_EXTRA_REGISTERS: u32 = 6;
                let first = f
                    .frame_size
                    .checked_sub(CALL_EXTRA_REGISTERS + 1)
                    .ok_or_else(|| unsupported(f, op, "frame is too small for call arguments"))?;
                let last = first.checked_sub(argument_count - 1).ok_or_else(|| {
                    unsupported(f, op, "argument count exceeds the function frame")
                })?;
                let this_arg = register_number(f, first)?;
                let args = (last..first)
                    .rev()
                    .map(|register| register_number(f, register))
                    .collect::<Result<Vec<_>, _>>()?;
                b::call(b::id("_apply"), vec![r(1)?, this_arg, b::array(args)])
            }
            // Array literals create intrinsic arrays without consulting a
            // replaceable global Array constructor.
            "NewArray" => b::sparse_array(
                usize::try_from(uint(op, 1)?)
                    .map_err(|_| unsupported(f, op, "array length does not fit this platform"))?,
            ),
            "NewArrayWithBuffer" | "NewArrayWithBufferLong" => {
                let length = uint(op, 1)?;
                let literal_count = uint(op, 2)?;
                if literal_count > length {
                    return Err(unsupported(f, op, "literal count exceeds the array length"));
                }
                let values = self.literal_values(f, op, uint(op, 3)?, literal_count)?;
                b::array_with_trailing_holes(
                    values,
                    usize::try_from(length).map_err(|_| {
                        unsupported(f, op, "array length does not fit this platform")
                    })?,
                )
            }
            "NewObjectWithBuffer" | "NewObjectWithBufferLong" => {
                // Operand 1 is only a preallocation hint. The static property
                // count and the two serialized-buffer offsets are authoritative.
                b::object(self.object_entries(f, op, uint(op, 2)?, uint(op, 3)?, uint(op, 4)?)?)
            }
            "NewObjectWithParent" => b::object_with_parent(r(1)?),
            "PutOwnByIndex"
            | "PutOwnByIndexL"
            | "DefineOwnByIndex"
            | "DefineOwnByIndexL"
            | "DefineOwnInDenseArray"
            | "DefineOwnInDenseArrayL" => {
                return Ok(define_own(
                    r(0)?,
                    b::number(f64::from(uint(op, 2)?)),
                    r(1)?,
                    true,
                ));
            }
            "PutNewOwnByIdShort"
            | "PutNewOwnById"
            | "PutNewOwnByIdLong"
            | "PutNewOwnNEById"
            | "PutNewOwnNEByIdLong" => {
                return Ok(define_own(
                    r(0)?,
                    b::string(&self.string(uint(op, 2)?)?),
                    r(1)?,
                    !op.name.starts_with("PutNewOwnNE"),
                ));
            }
            "PutOwnByVal" => {
                let enumerable = match uint(op, 3)? {
                    0 => false,
                    1 => true,
                    _ => return Err(unsupported(f, op, "invalid enumerable flag")),
                };
                return Ok(define_own(r(0)?, r(2)?, r(1)?, enumerable));
            }
            "NewObject" => b::empty_object(),
            name if binary_op(name).is_some() => b::binary(binary_op(name).unwrap(), r(1)?, r(2)?),
            "Not" => b::unary(UnaryOp::Bang, r(1)?),
            "Negate" => b::unary(UnaryOp::Minus, r(1)?),
            "BitNot" => b::unary(UnaryOp::Tilde, r(1)?),
            "TypeOf" => b::unary(UnaryOp::TypeOf, r(1)?),
            _ => return Err(unsupported(f, op, "opcode has no verified SWC lowering")),
        };
        Ok(vec![b::assign(r(0)?, value)])
    }

    fn literal_values(
        &self,
        f: &RawFunction,
        op: &RawInstruction,
        offset: u32,
        count: u32,
    ) -> Result<Vec<Expr>, Error> {
        self.buffer_values(
            f,
            op,
            &self.container.literal_value_buffer,
            offset,
            count,
        )
    }

    fn big_int(&self, id: u32) -> Result<String, Error> {
        let entry = self
            .container
            .big_int_entries
            .get(id as usize)
            .ok_or_else(|| Error::Bytecode(format!("invalid bigint {id}")))?;
        let start = entry.first as usize;
        let end = start
            .checked_add(entry.second as usize)
            .ok_or_else(|| Error::Bytecode("bigint storage range overflows".into()))?;
        let bytes = self
            .container
            .big_int_storage
            .get(start..end)
            .ok_or_else(|| Error::Bytecode(format!("invalid bigint {id}")))?;
        Ok(BigInt::from_signed_bytes_le(bytes).to_string())
    }

    fn buffer_values(
        &self,
        f: &RawFunction,
        op: &RawInstruction,
        buffer: &[u8],
        offset: u32,
        count: u32,
    ) -> Result<Vec<Expr>, Error> {
        literal::decode_buffer(buffer, offset, count)?
            .into_iter()
            .map(|value| match value {
                literal::LiteralValue::Null => Ok(*b::null()),
                literal::LiteralValue::Bool(value) => Ok(*b::boolean(value)),
                literal::LiteralValue::Number(value) if value.is_finite() => Ok(*b::number(value)),
                literal::LiteralValue::Number(_) => {
                    Err(unsupported(f, op, "non-finite buffered number"))
                }
                literal::LiteralValue::String(id) => Ok(*b::string(&self.string(id)?)),
            })
            .collect()
    }

    fn object_entries(
        &self,
        f: &RawFunction,
        op: &RawInstruction,
        count: u32,
        key_offset: u32,
        value_offset: u32,
    ) -> Result<Vec<(Expr, Expr)>, Error> {
        let keys = literal::decode_buffer(&self.container.object_key_buffer, key_offset, count)?;
        let values = self.buffer_values(
            f,
            op,
            &self.container.object_value_buffer,
            value_offset,
            count,
        )?;
        keys.into_iter()
            .zip(values)
            .map(|(key, value)| {
                let key = match key {
                    literal::LiteralValue::String(id) => *b::string(&self.string(id)?),
                    literal::LiteralValue::Number(number)
                        if number.is_finite()
                            && number >= 0.0
                            && number <= f64::from(u32::MAX)
                            && number.fract() == 0.0 =>
                    {
                        *b::number(number)
                    }
                    _ => return Err(unsupported(f, op, "invalid buffered object key")),
                };
                Ok((key, value))
            })
            .collect()
    }
}
fn uint(op: &RawInstruction, index: usize) -> Result<u32, Error> {
    match op.operands.get(index) {
        Some(RawOperand::U8(v)) => Ok(u32::from(*v)),
        Some(RawOperand::U16(v)) => Ok(u32::from(*v)),
        Some(RawOperand::U32(v)) => Ok(*v),
        _ => Err(Error::Bytecode(format!(
            "invalid operand {index} for {}",
            op.name
        ))),
    }
}
fn register(f: &RawFunction, op: &RawInstruction, index: usize) -> Result<Box<Expr>, Error> {
    let r = uint(op, index)?;
    register_number(f, r)
}
fn register_number(f: &RawFunction, register: u32) -> Result<Box<Expr>, Error> {
    let r = register;
    if r >= f.frame_size {
        return Err(Error::Bytecode(format!(
            "register {r} outside function {} frame",
            f.function_index
        )));
    }
    Ok(b::id(&format!("_r{r}")))
}
fn environment_slot(op: &RawInstruction, index: usize) -> Result<Box<Expr>, Error> {
    let slot = uint(op, index)?;
    let index = slot
        .checked_add(1)
        .ok_or_else(|| Error::Bytecode("environment slot overflows address space".into()))?;
    Ok(b::number(f64::from(index)))
}
fn unsupported(f: &RawFunction, op: &RawInstruction, reason: &str) -> Error {
    Error::Unsupported(format!(
        "function {} offset 0x{:x}: {}: {reason}",
        f.function_index, op.offset, op.name
    ))
}
fn is_define_own(name: &str) -> bool {
    matches!(
        name,
        "PutOwnByIndex"
            | "PutOwnByIndexL"
            | "DefineOwnByIndex"
            | "DefineOwnByIndexL"
            | "DefineOwnInDenseArray"
            | "DefineOwnInDenseArrayL"
            | "PutNewOwnByIdShort"
            | "PutNewOwnById"
            | "PutNewOwnByIdLong"
            | "PutNewOwnNEById"
            | "PutNewOwnNEByIdLong"
            | "PutOwnByVal"
    )
}
fn has_opcode(raw: &RawModule, name: &str) -> bool {
    raw.functions
        .iter()
        .flat_map(|function| &function.instructions)
        .any(|op| op.name == name)
}
fn define_own(object: Box<Expr>, key: Box<Expr>, value: Box<Expr>, enumerable: bool) -> Vec<Stmt> {
    vec![
        b::assign(b::id("_desc"), b::empty_object()),
        b::assign(b::member(b::id("_desc"), b::string("value")), value),
        b::assign(
            b::member(b::id("_desc"), b::string("writable")),
            b::boolean(true),
        ),
        b::assign(
            b::member(b::id("_desc"), b::string("enumerable")),
            b::boolean(enumerable),
        ),
        b::assign(
            b::member(b::id("_desc"), b::string("configurable")),
            b::boolean(true),
        ),
        b::expr(b::call(b::id("_define"), vec![object, key, b::id("_desc")])),
    ]
}
fn set_pc(target: u32) -> Stmt {
    b::assign(b::id("_pc"), b::number(f64::from(target)))
}
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && !matches!(
            name,
            "default"
                | "class"
                | "var"
                | "let"
                | "const"
                | "function"
                | "return"
                | "this"
                | "super"
                | "new"
                | "delete"
                | "in"
                | "instanceof"
                | "if"
                | "else"
                | "while"
                | "for"
                | "switch"
                | "case"
                | "break"
                | "continue"
                | "throw"
                | "try"
                | "catch"
                | "finally"
                | "with"
                | "debugger"
                | "do"
                | "void"
                | "typeof"
                | "null"
                | "true"
                | "false"
                | "import"
                | "export"
                | "extends"
                | "enum"
                | "yield"
                | "await"
                | "implements"
                | "interface"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "static"
        )
}
fn binary_op(name: &str) -> Option<BinaryOp> {
    Some(match name {
        "Add" | "AddN" => BinaryOp::Add,
        "Sub" | "SubN" => BinaryOp::Sub,
        "Mul" | "MulN" => BinaryOp::Mul,
        "Div" | "DivN" => BinaryOp::Div,
        "Mod" => BinaryOp::Mod,
        "Greater" => BinaryOp::Gt,
        "GreaterEq" => BinaryOp::GtEq,
        "Less" => BinaryOp::Lt,
        "LessEq" => BinaryOp::LtEq,
        "Eq" => BinaryOp::EqEq,
        "Neq" => BinaryOp::NotEq,
        "StrictEq" => BinaryOp::EqEqEq,
        "StrictNeq" => BinaryOp::NotEqEq,
        "BitAnd" => BinaryOp::BitAnd,
        "BitOr" => BinaryOp::BitOr,
        "BitXor" => BinaryOp::BitXor,
        "LShift" => BinaryOp::LShift,
        "RShift" => BinaryOp::RShift,
        "URshift" | "URShift" => BinaryOp::ZeroFillRShift,
        "InstanceOf" => BinaryOp::InstanceOf,
        "IsIn" => BinaryOp::In,
        _ => return None,
    })
}
fn branch_condition(f: &RawFunction, op: &RawInstruction) -> Result<Box<Expr>, Error> {
    let name = op.name.strip_suffix("Long").unwrap_or(&op.name);
    let name = name.strip_suffix('N').unwrap_or(name);
    let a = register(f, op, 1)?;
    match name {
        "JmpTrue" => return Ok(a),
        "JmpFalse" => return Ok(b::unary(UnaryOp::Bang, a)),
        "JmpUndefined" => return Ok(b::binary(BinaryOp::EqEqEq, a, b::undefined())),
        _ => {}
    }
    let (kind, invert) = match name {
        "JGreater" => (BinaryOp::Gt, false),
        "JGreaterEqual" => (BinaryOp::GtEq, false),
        "JLess" => (BinaryOp::Lt, false),
        "JLessEqual" => (BinaryOp::LtEq, false),
        "JNotGreater" => (BinaryOp::Gt, true),
        "JNotGreaterEqual" => (BinaryOp::GtEq, true),
        "JNotLess" => (BinaryOp::Lt, true),
        "JNotLessEqual" => (BinaryOp::LtEq, true),
        "JEqual" => (BinaryOp::EqEq, false),
        "JNotEqual" => (BinaryOp::NotEq, false),
        "JStrictEqual" => (BinaryOp::EqEqEq, false),
        "JStrictNotEqual" => (BinaryOp::NotEqEq, false),
        _ => return Err(unsupported(f, op, "unsupported conditional")),
    };
    let expr = b::binary(kind, a, register(f, op, 2)?);
    Ok(if invert {
        b::unary(UnaryOp::Bang, expr)
    } else {
        expr
    })
}

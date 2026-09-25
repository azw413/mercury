use crate::{Error, SwcModule, ast_builder as b, cfg, literal};
use mercury_binary::{HbcContainer, decode_raw_module, parse_hbc_container_with_spec};
use mercury_ir::{RawFunction, RawInstruction, RawModule, RawOperand};
use num_bigint::BigInt;
use std::collections::HashSet;
use swc_core::{
    common::{DUMMY_SP, FileName, SourceMap, sync::Lrc},
    ecma::{
        ast::*,
        parser::{Parser, StringInput, Syntax, lexer::Lexer},
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
    // The async bit records the presence of async functions; unlike static
    // builtins and statically resolved modules it does not change opcode meaning.
    if h.options.raw & !0b100 != 0
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
    let mut needs_define = raw
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
    let resumable_functions = raw
        .functions
        .iter()
        .map(|function| has_function_opcode(function, "StartGenerator"))
        .collect::<Vec<_>>();
    let argument_functions = raw
        .functions
        .iter()
        .map(|function| {
            function.instructions.iter().any(|op| {
                matches!(
                    op.name.as_str(),
                    "ReifyArguments" | "GetArgumentsPropByVal" | "GetArgumentsLength"
                )
            })
        })
        .collect::<Vec<_>>();
    let needs_arguments = argument_functions.iter().any(|value| *value);
    let needs_suspension = resumable_functions.iter().any(|value| *value);
    let needs_numeric_runtime = ["Inc", "Dec", "ToNumeric"]
        .into_iter()
        .any(|name| has_opcode(&raw, name));
    let needs_construction = raw.functions.iter().any(|function| {
        function.flags.prohibit_invoke != 2
            || function.instructions.iter().any(|op| {
                matches!(
                    op.name.as_str(),
                    "Construct" | "ConstructLong" | "CreateThis" | "SelectObject" | "GetNewTarget"
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
    let needs_function_name_runtime = names.iter().any(|name| accessor_name(name));
    needs_define |= needs_function_name_runtime;
    let mut prefix = "_mercury".to_owned();
    while names.iter().any(|name| name.starts_with(&prefix)) {
        prefix.push('_');
    }
    let mut factories = Vec::new();
    if needs_numeric_runtime {
        factories.extend(numeric_runtime());
    }
    if needs_function_name_runtime {
        factories.extend(function_name_runtime());
    }
    if needs_construction {
        factories.extend(construction_runtime());
    }
    if needs_suspension {
        factories.extend(suspension_runtime());
    }
    for f in &raw.functions {
        if f.frame_size > 65_536 {
            return Err(Error::Unsupported(
                "decompiler register budget exceeded".into(),
            ));
        }
        if f.flags.prohibit_invoke > 2 {
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
        // Hermes uses non-JavaScript labels such as `#method#` for class
        // method bodies. The class-definition helpers install their observable
        // names, so these labels must not become function-expression bindings.
        let generated_name = name.starts_with("?anon_")
            || (name.starts_with('#') && name.ends_with('#'))
            || accessor_name(&name);
        if !name.is_empty() && !generated_name && !valid_name(&name) {
            return Err(Error::Unsupported(format!("function name {name:?}")));
        }
        let params = (1..f.param_count).map(|i| format!("_a{i}")).collect();
        let mut function = b::function(
            if name.is_empty() || generated_name {
                None
            } else {
                Some(&name)
            },
            params,
            lower.function(
                f,
                resumable_functions[f.function_index],
                needs_construction,
                argument_functions[f.function_index],
            )?,
        );
        if accessor_name(&name) {
            function = b::call(b::id("_name_function"), vec![function, b::string(&name)]);
        }
        if needs_construction {
            function = b::call(b::id("_mark_function"), vec![function]);
        }
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
    if needs_suspension {
        for (name, global) in [("_promise", "Promise"), ("_symbol", "Symbol")] {
            wrapper_params.push(name.into());
            wrapper_args.push(b::member(b::this(), b::string(global)));
        }
    }
    if needs_arguments {
        wrapper_params.push("_slice".into());
        wrapper_args.push(b::member(
            b::member(
                b::member(b::this(), b::string("Array")),
                b::string("prototype"),
            ),
            b::string("slice"),
        ));
    }
    if needs_construction {
        for (name, value) in [
            (
                "_object_create",
                b::member(
                    b::member(b::this(), b::string("Object")),
                    b::string("create"),
                ),
            ),
            (
                "_object_prototype",
                b::member(
                    b::member(b::this(), b::string("Object")),
                    b::string("prototype"),
                ),
            ),
            ("_weak_set", b::member(b::this(), b::string("WeakSet"))),
        ] {
            wrapper_params.push(name.into());
            wrapper_args.push(value);
        }
    }
    if needs_suspension || needs_construction {
        wrapper_params.push("_type_error".into());
        wrapper_args.push(b::member(b::this(), b::string("TypeError")));
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
    fn function(
        &self,
        f: &RawFunction,
        resumable: bool,
        construction_runtime: bool,
        uses_arguments: bool,
    ) -> Result<Vec<Stmt>, Error> {
        let mut body = Vec::new();
        if f.flags.strict_mode {
            body.push(b::expr(b::string("use strict")));
        }
        if construction_runtime {
            body.push(b::var(
                "_function_new_target",
                Some(b::binary(
                    BinaryOp::LogicalOr,
                    b::new_target(),
                    b::call(b::id("_enter_function"), vec![]),
                )),
            ));
            let prohibited = match f.flags.prohibit_invoke {
                0 => Some(b::binary(
                    BinaryOp::EqEqEq,
                    b::id("_function_new_target"),
                    b::undefined(),
                )),
                1 => Some(b::binary(
                    BinaryOp::NotEqEq,
                    b::id("_function_new_target"),
                    b::undefined(),
                )),
                _ => None,
            };
            if let Some(test) = prohibited {
                body.push(Stmt::If(IfStmt {
                    span: DUMMY_SP,
                    test,
                    cons: Box::new(Stmt::Throw(ThrowStmt {
                        span: DUMMY_SP,
                        arg: b::new(
                            b::id("_type_error"),
                            vec![b::string("invalid function invocation")],
                        ),
                    })),
                    alt: None,
                }));
            }
        }
        if resumable {
            body.push(b::var("_this", Some(b::this())));
            body.push(b::var("_args", Some(b::id("arguments"))));
        }
        if uses_arguments {
            body.push(b::var(
                "_param_args",
                Some(b::call(
                    b::id("_apply"),
                    vec![b::id("_slice"), b::id("arguments"), b::array(vec![])],
                )),
            ));
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
        if resumable {
            body.push(b::var("_suspended", Some(b::boolean(false))));
            body.push(b::var("_delegated", Some(b::boolean(false))));
        }
        let deferred_constructor_prototypes = f
            .instructions
            .windows(2)
            .filter_map(|pair| {
                let get = &pair[0];
                let create = &pair[1];
                if !matches!(
                    get.name.as_str(),
                    "GetById" | "GetByIdShort" | "GetByIdLong"
                ) || create.name != "CreateThis"
                {
                    return None;
                }
                Some((get, create))
            })
            .map(|(get, create)| {
                let is_constructor_prototype = uint(get, 0)? == uint(create, 1)?
                    && uint(get, 1)? == uint(create, 2)?
                    && self.string(uint(get, 3)?)? == "prototype";
                Ok(is_constructor_prototype.then_some(get.offset))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .flatten()
            .collect::<HashSet<_>>();
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
                            let value = table
                                .min_case
                                .checked_add(index as u32)
                                .ok_or_else(|| unsupported(f, op, "switch case value overflows"))?;
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
                    stmts.extend(self.instruction(
                        f,
                        op,
                        resumable,
                        uses_arguments,
                        deferred_constructor_prototypes.contains(&op.offset),
                    )?);
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
        let dispatch_loop = Stmt::While(WhileStmt {
            span: DUMMY_SP,
            test: b::boolean(true),
            body: Box::new(Stmt::Block(b::block(loop_body))),
        });
        if resumable {
            body.push(b::ret(b::function(
                None,
                vec!["_action".into(), "_resume".into()],
                vec![dispatch_loop],
            )));
        } else {
            body.push(dispatch_loop);
        }
        Ok(body)
    }
    fn instruction(
        &self,
        f: &RawFunction,
        op: &RawInstruction,
        resumable: bool,
        uses_arguments: bool,
        deferred_constructor_prototype: bool,
    ) -> Result<Vec<Stmt>, Error> {
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
            "CreateClosure"
            | "CreateClosureLongIndex"
            | "CreateGeneratorClosure"
            | "CreateGeneratorClosureLongIndex"
            | "CreateAsyncClosure"
            | "CreateAsyncClosureLongIndex" => {
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
            "GetNewTarget" => b::id("_function_new_target"),
            "LoadParam" | "LoadParamLong" => {
                let index = uint(op, 1)?;
                if index == 0 {
                    if resumable { b::id("_this") } else { b::this() }
                } else {
                    b::member(
                        if uses_arguments {
                            b::id("_param_args")
                        } else if resumable {
                            b::id("_args")
                        } else {
                            b::id("arguments")
                        },
                        b::number(f64::from(index - 1)),
                    )
                }
            }
            "LoadThisNS" => {
                if resumable {
                    b::id("_this")
                } else {
                    b::this()
                }
            }
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
            "LoadConstBigInt" | "LoadConstBigIntLongIndex" => b::call(
                b::id("_bigint"),
                vec![b::string(&self.big_int(uint(op, 1)?)?)],
            ),
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
            "Ret" if resumable => {
                return Ok(vec![Stmt::If(IfStmt {
                    span: DUMMY_SP,
                    test: b::id("_suspended"),
                    cons: Box::new(Stmt::Block(b::block(vec![
                        b::assign(b::id("_suspended"), b::boolean(false)),
                        Stmt::If(IfStmt {
                            span: DUMMY_SP,
                            test: b::id("_delegated"),
                            cons: Box::new(Stmt::Block(b::block(vec![
                                b::assign(b::id("_delegated"), b::boolean(false)),
                                b::ret(r(0)?),
                            ]))),
                            alt: None,
                        }),
                        b::ret(iterator_result(*r(0)?, false)),
                    ]))),
                    alt: Some(Box::new(b::ret(iterator_result(*r(0)?, true)))),
                })]);
            }
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
                let value = if deferred_constructor_prototype {
                    b::call(b::id("_constructor_prototype"), vec![r(1)?])
                } else {
                    b::member(r(1)?, b::string(&key))
                };
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
            "DelById" | "DelByIdLong" => b::unary(
                UnaryOp::Delete,
                b::member(r(1)?, b::string(&self.string(uint(op, 2)?)?)),
            ),
            "DelByVal" => b::unary(UnaryOp::Delete, b::member(r(1)?, r(2)?)),
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
            "Construct" | "ConstructLong" => {
                let argument_count = uint(op, 2)?;
                if argument_count == 0 {
                    return Err(unsupported(f, op, "construct has no this argument"));
                }
                const CALL_EXTRA_REGISTERS: u32 = 6;
                let first = f
                    .frame_size
                    .checked_sub(CALL_EXTRA_REGISTERS + 1)
                    .ok_or_else(|| {
                        unsupported(f, op, "frame is too small for construct arguments")
                    })?;
                let last = first.checked_sub(argument_count - 1).ok_or_else(|| {
                    unsupported(f, op, "construct argument count exceeds the function frame")
                })?;
                let this_arg = register_number(f, first)?;
                let args = (last..first)
                    .rev()
                    .map(|register| register_number(f, register))
                    .collect::<Result<Vec<_>, _>>()?;
                let external_construct =
                    b::function(None, vec![], vec![b::ret(b::new(r(1)?, args.clone()))]);
                b::call(
                    b::id("_construct_value"),
                    vec![r(1)?, this_arg, b::array(args), external_construct],
                )
            }
            "CallBuiltin" | "CallBuiltinLong" => {
                let builtin = uint(op, 1)?;
                let argument_count = uint(op, 2)?;
                if argument_count == 0 {
                    return Err(unsupported(f, op, "builtin call has no this argument"));
                }
                const CALL_EXTRA_REGISTERS: u32 = 6;
                let first = f
                    .frame_size
                    .checked_sub(CALL_EXTRA_REGISTERS + 1)
                    .ok_or_else(|| {
                        unsupported(f, op, "frame is too small for builtin arguments")
                    })?;
                let last = first.checked_sub(argument_count - 1).ok_or_else(|| {
                    unsupported(f, op, "builtin argument count exceeds the function frame")
                })?;
                let args = (last..first)
                    .rev()
                    .map(|register| register_number(f, register))
                    .collect::<Result<Vec<_>, _>>()?;
                // HBC remained at version 96 across Hermes 0.12 and 0.13 even
                // though four private builtins moved from 40..=43 to 45..=48.
                // A yield* body always contains generatorSetDelegated, so that
                // sentinel identifies the producer's contiguous builtin range.
                let modern_yield_builtins = f.instructions.iter().any(|instruction| {
                    matches!(instruction.name.as_str(), "CallBuiltin" | "CallBuiltinLong")
                        && matches!(
                            instruction.operands.get(1),
                            Some(RawOperand::U8(48) | RawOperand::U32(48))
                        )
                });
                let ensure_object = if modern_yield_builtins { 45 } else { 40 };
                match builtin {
                    value if resumable && value == ensure_object => {
                        b::call(b::id("_ensure_object"), args)
                    }
                    value if resumable && value == ensure_object + 1 => {
                        b::call(b::id("_get_method"), args)
                    }
                    value if resumable && value == ensure_object + 2 => {
                        b::call(b::id("_throw_type_error"), args)
                    }
                    value if resumable && value == ensure_object + 3 => {
                        return Ok(vec![
                            b::assign(b::id("_delegated"), b::boolean(true)),
                            b::assign(r(0)?, b::undefined()),
                        ]);
                    }
                    _ => return Err(unsupported(f, op, "unsupported builtin call")),
                }
            }
            "GetBuiltinClosure" => {
                let async_driver = f
                    .instructions
                    .iter()
                    .any(|instruction| instruction.name == "ReifyArguments")
                    && f.instructions.iter().any(|instruction| {
                        matches!(
                            instruction.name.as_str(),
                            "CreateGeneratorClosure" | "CreateGeneratorClosureLongIndex"
                        )
                    });
                if !async_driver {
                    return Err(unsupported(f, op, "unsupported builtin closure"));
                }
                b::id("_spawn_async")
            }
            "ReifyArguments" => {
                if resumable {
                    b::id("_args")
                } else {
                    b::id("arguments")
                }
            }
            "GetArgumentsPropByVal" => b::member(
                if resumable {
                    b::id("_args")
                } else {
                    b::id("arguments")
                },
                r(1)?,
            ),
            "GetArgumentsLength" => b::member(
                if resumable {
                    b::id("_args")
                } else {
                    b::id("arguments")
                },
                b::string("length"),
            ),
            "CreateGenerator" | "CreateGeneratorLongIndex" => {
                let target = uint(op, 2)?;
                if target as usize >= self.raw.functions.len() {
                    return Err(Error::Bytecode("invalid generator target".into()));
                }
                b::call(
                    b::id("_generator"),
                    vec![
                        b::call(b::id(&format!("_make{target}")), vec![r(1)?]),
                        if resumable { b::id("_this") } else { b::this() },
                        if resumable {
                            b::id("_args")
                        } else {
                            b::id("arguments")
                        },
                    ],
                )
            }
            "CreateThis" => b::call(b::id("_create_this"), vec![r(1)?]),
            "SelectObject" => b::call(b::id("_select_object"), vec![r(1)?, r(2)?]),
            "StartGenerator" | "CompleteGenerator" => return Ok(vec![]),
            "ResumeGenerator" => {
                if !resumable {
                    return Err(unsupported(f, op, "resume outside a resumable function"));
                }
                return Ok(vec![
                    Stmt::If(IfStmt {
                        span: DUMMY_SP,
                        test: b::binary(BinaryOp::EqEqEq, b::id("_action"), b::string("throw")),
                        cons: Box::new(Stmt::Throw(ThrowStmt {
                            span: DUMMY_SP,
                            arg: b::id("_resume"),
                        })),
                        alt: None,
                    }),
                    b::assign(r(0)?, b::id("_resume")),
                    b::assign(
                        r(1)?,
                        b::binary(BinaryOp::EqEqEq, b::id("_action"), b::string("return")),
                    ),
                ]);
            }
            "SaveGenerator" => {
                if !resumable {
                    return Err(unsupported(f, op, "save outside a resumable function"));
                }
                return Ok(vec![
                    set_pc(cfg::relative_target(op, 0)?),
                    b::assign(b::id("_suspended"), b::boolean(true)),
                ]);
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
            "PutOwnGetterSetterByVal" => {
                let enumerable = match uint(op, 4)? {
                    0 => false,
                    1 => true,
                    _ => return Err(unsupported(f, op, "invalid enumerable flag")),
                };
                return Ok(define_accessor(r(0)?, r(1)?, r(2)?, r(3)?, enumerable));
            }
            "NewObject" => b::empty_object(),
            "Inc" => b::call(b::id("_increment"), vec![r(1)?]),
            "Dec" => b::call(b::id("_decrement"), vec![r(1)?]),
            "ToNumber" => b::unary(UnaryOp::Plus, r(1)?),
            "ToNumeric" => b::call(b::id("_to_numeric"), vec![r(1)?]),
            "ToInt32" => b::binary(BinaryOp::BitOr, r(1)?, b::number(0.0)),
            "AddEmptyString" => b::binary(BinaryOp::Add, b::string(""), r(1)?),
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
        self.buffer_values(f, op, &self.container.literal_value_buffer, offset, count)
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
            | "PutOwnGetterSetterByVal"
    )
}
fn accessor_name(name: &str) -> bool {
    name.starts_with("get ") || name.starts_with("set ")
}
fn has_opcode(raw: &RawModule, name: &str) -> bool {
    raw.functions
        .iter()
        .flat_map(|function| &function.instructions)
        .any(|op| op.name == name)
}
fn has_function_opcode(function: &RawFunction, name: &str) -> bool {
    function.instructions.iter().any(|op| op.name == name)
}
fn numeric_runtime() -> Vec<Stmt> {
    const SOURCE: &str = r#"
function _increment(_value) {
    return ++_value;
}
function _decrement(_value) {
    return --_value;
}
function _to_numeric(_value) {
    return _value++;
}
"#;
    embedded_runtime("mercury-numeric-runtime.js", SOURCE)
}
fn function_name_runtime() -> Vec<Stmt> {
    const SOURCE: &str = r#"
function _name_function(_function, _name) {
    _define(_function, "name", { value: _name, configurable: true });
    return _function;
}
"#;
    embedded_runtime("mercury-function-name-runtime.js", SOURCE)
}
fn construction_runtime() -> Vec<Stmt> {
    const SOURCE: &str = r#"
var _recovered_functions = new _weak_set();
var _new_target_stack = [];
var _external_constructor = {};
function _mark_function(_function) {
    _recovered_functions["add"](_function);
    return _function;
}
function _enter_function() {
    var _entry = _new_target_stack[_new_target_stack["length"] - 1];
    if (_entry !== void 0 && _entry["pending"]) {
        _entry["pending"] = false;
        return _entry["target"];
    }
    return void 0;
}
function _construct_value(_function, _this_value, _arguments_value, _external_construct) {
    if (_recovered_functions["has"](_function)) {
        _new_target_stack["push"]({ target: _function, pending: true });
        try {
            return _apply(_function, _this_value, _arguments_value);
        } finally {
            _new_target_stack["pop"]();
        }
    }
    return _external_construct();
}
function _constructor_prototype(_function) {
    if (_recovered_functions["has"](_function)) {
        return _function["prototype"];
    }
    return _external_constructor;
}
function _create_this(_prototype) {
    if (_prototype === _external_constructor) return _prototype;
    if (_prototype === null || typeof _prototype === "object" || typeof _prototype === "function") {
        return _object_create(_prototype);
    }
    return _object_create(_object_prototype);
}
function _select_object(_this_value, _return_value) {
    if (_return_value !== null &&
        (typeof _return_value === "object" || typeof _return_value === "function")) {
        return _return_value;
    }
    return _this_value;
}
"#;
    embedded_runtime("mercury-construction-runtime.js", SOURCE)
}
fn suspension_runtime() -> Vec<Stmt> {
    const SOURCE: &str = r#"
function _generator(_init, _this_value, _arguments_value) {
    var _step = _apply(_init, _this_value, _arguments_value);
    var _done = false;
    var _started = false;
    var _running = false;
    var _iterator = {};
    function _resume_generator(_action_value, _sent_value) {
        if (_running) throw new _type_error("Generator is already running");
        if (_done) {
            if (_action_value === "throw") throw _sent_value;
            return { value: _action_value === "return" ? _sent_value : void 0, done: true };
        }
        if (!_started) {
            _started = true;
            if (_action_value === "next") _sent_value = void 0;
        }
        _running = true;
        try {
            var _result = _step(_action_value, _sent_value);
            _done = _result["done"];
            return _result;
        } catch (_error) {
            _done = true;
            throw _error;
        } finally {
            _running = false;
        }
    }
    _iterator["next"] = function(_value) { return _resume_generator("next", _value); };
    _iterator["throw"] = function(_value) { return _resume_generator("throw", _value); };
    _iterator["return"] = function(_value) { return _resume_generator("return", _value); };
    _iterator[_symbol["iterator"]] = function() { return this; };
    return _iterator;
}
function _spawn_async(_generator_function, _this_value, _arguments_value) {
    return new _promise(function(_resolve, _reject) {
        var _iterator = _apply(_generator_function, _this_value, _arguments_value);
        function _advance(_action_value, _sent_value) {
            var _result;
            try {
                _result = _iterator[_action_value](_sent_value);
            } catch (_error) {
                _reject(_error);
                return;
            }
            if (_result["done"]) {
                _resolve(_result["value"]);
                return;
            }
            _promise["resolve"](_result["value"])["then"](
                function(_value) { _advance("next", _value); },
                function(_error) { _advance("throw", _error); }
            );
        }
        _advance("next", void 0);
    });
}
function _ensure_object(_value, _message) {
    if (_value === null || (typeof _value !== "object" && typeof _value !== "function")) {
        throw new _type_error(_message);
    }
    return _value;
}
function _get_method(_value, _key) {
    var _method = _value[_key];
    if (_method === null || _method === void 0) return void 0;
    if (typeof _method !== "function") throw new _type_error(_key + " is not callable");
    return _method;
}
function _throw_type_error(_message) {
    throw new _type_error(_message);
}
"#;
    embedded_runtime("mercury-suspension-runtime.js", SOURCE)
}
fn embedded_runtime(name: &str, source: &'static str) -> Vec<Stmt> {
    let source_map: Lrc<SourceMap> = Default::default();
    let file = source_map.new_source_file(FileName::Custom(name.into()).into(), source);
    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        EsVersion::latest(),
        StringInput::from(&*file),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    parser
        .parse_script()
        .expect("embedded decompiler runtime must parse")
        .body
}
fn iterator_result(value: Expr, done: bool) -> Box<Expr> {
    b::object(vec![
        (*b::string("value"), value),
        (*b::string("done"), *b::boolean(done)),
    ])
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
fn define_accessor(
    object: Box<Expr>,
    key: Box<Expr>,
    getter: Box<Expr>,
    setter: Box<Expr>,
    enumerable: bool,
) -> Vec<Stmt> {
    vec![
        b::assign(b::id("_desc"), b::empty_object()),
        b::assign(b::member(b::id("_desc"), b::string("get")), getter),
        b::assign(b::member(b::id("_desc"), b::string("set")), setter),
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

use std::collections::HashMap;

use mercury_binary::{
    DecodedInstruction, DecodedOperand, MinimalFunction, MinimalModule, StringKind,
    build_minimal_module,
};
use swc_core::ecma::ast::{
    AssignOp, AssignTarget, BinaryOp, BlockStmt, Callee, Decl, Expr, Lit, MemberExpr, MemberProp,
    Pat, Program, Script, SimpleAssignTarget, Stmt, UnaryOp, VarDecl, VarDeclKind,
};

use crate::{Error, SwcModule};

/// Native SWC-AST to Hermes-bytecode compiler.
///
/// The initial compiler targets HBC 96 global scripts. Unsupported syntax is
/// reported explicitly instead of being delegated to an installed `hermesc`.
pub struct HbcCompiler {
    target_version: u32,
}

impl HbcCompiler {
    pub fn new(target_version: u32) -> Self {
        Self { target_version }
    }

    pub fn compile(&self, module: &SwcModule) -> Result<Vec<u8>, Error> {
        if self.target_version != 96 {
            return Err(Error::Unsupported(
                "native compilation currently targets HBC 96".into(),
            ));
        }
        let program = module.javascript_program();
        let Program::Script(script) = program else {
            return Err(Error::Unsupported(
                "ES modules must be bundled into a script before native compilation".into(),
            ));
        };
        Compiler::new(self.target_version).compile_script(&script)
    }
}

struct Compiler {
    version: u32,
    instructions: Vec<DecodedInstruction>,
    strings: Vec<String>,
    string_kinds: Vec<StringKind>,
    string_ids: HashMap<String, u32>,
    next_register: u16,
    frame_size: u16,
    max_call_arguments: u16,
    next_cache: u16,
}

impl Compiler {
    fn new(version: u32) -> Self {
        Self {
            version,
            instructions: Vec::new(),
            strings: Vec::new(),
            string_kinds: Vec::new(),
            string_ids: HashMap::new(),
            next_register: 0,
            frame_size: 0,
            max_call_arguments: 0,
            next_cache: 0,
        }
    }

    fn compile_script(mut self, script: &Script) -> Result<Vec<u8>, Error> {
        let mut declarations = Vec::new();
        collect_var_declarations(&script.body, &mut declarations)?;
        declarations.sort();
        declarations.dedup();
        for name in declarations {
            let id = self.intern_identifier(&name)?;
            self.emit("DeclareGlobalVar", vec![DecodedOperand::U32(id)]);
        }

        let mut directive_prologue = true;
        for statement in &script.body {
            if directive_prologue && is_string_expression(statement) {
                return Err(Error::Unsupported(
                    "directive prologues are not supported by native compilation yet".into(),
                ));
            }
            directive_prologue = false;
            self.compile_statement(statement)?;
            debug_assert_eq!(self.next_register, 0);
        }

        let result = self.alloc_register()?;
        self.emit("LoadConstUndefined", vec![reg(result)]);
        self.emit("Ret", vec![reg(result)]);
        self.release_register(result)?;

        let spec = mercury_spec_builtin::load_spec(self.version)
            .ok_or_else(|| Error::Bytecode("missing embedded HBC 96 spec".into()))?;
        // Hermes reserves six caller registers plus the largest outgoing
        // argument area (including `this`) at the end of a function frame.
        let frame_size = if self.max_call_arguments == 0 {
            self.frame_size.max(1)
        } else {
            self.frame_size + 6 + self.max_call_arguments
        };
        if frame_size >= 128 {
            return Err(Error::Unsupported(
                "script needs a function frame too large for an HBC 96 small header".into(),
            ));
        }
        let module = MinimalModule {
            version: self.version,
            global_code_index: 0,
            strings: self.strings,
            string_kinds: self.string_kinds,
            literal_value_buffer: Vec::new(),
            object_key_buffer: Vec::new(),
            object_value_buffer: Vec::new(),
            functions: vec![MinimalFunction {
                name: "global".into(),
                param_count: 1,
                frame_size: u32::from(frame_size),
                environment_size: 0,
                instructions: self.instructions,
            }],
        };
        build_minimal_module(&module, &spec.bytecode)
            .map_err(|error| Error::Bytecode(error.to_string()))
    }

    fn compile_statement(&mut self, statement: &Stmt) -> Result<(), Error> {
        match statement {
            Stmt::Empty(_) => Ok(()),
            Stmt::Debugger(_) => {
                self.emit("Debugger", vec![]);
                Ok(())
            }
            Stmt::Expr(statement) => {
                let result = self.compile_expression(&statement.expr)?;
                self.release_register(result)
            }
            Stmt::Block(block) => self.compile_block(block),
            Stmt::Decl(Decl::Var(declaration)) => self.compile_var_declaration(declaration),
            other => Err(unsupported_statement(other)),
        }
    }

    fn compile_block(&mut self, block: &BlockStmt) -> Result<(), Error> {
        for statement in &block.stmts {
            self.compile_statement(statement)?;
        }
        Ok(())
    }

    fn compile_var_declaration(&mut self, declaration: &VarDecl) -> Result<(), Error> {
        if declaration.kind != VarDeclKind::Var {
            return Err(Error::Unsupported(
                "native compilation currently supports `var` declarations only".into(),
            ));
        }
        for declarator in &declaration.decls {
            let Pat::Ident(name) = &declarator.name else {
                return Err(Error::Unsupported(
                    "destructuring declarations are not supported by native compilation yet".into(),
                ));
            };
            if let Some(initializer) = &declarator.init {
                let value = self.compile_expression(initializer)?;
                let global = self.alloc_register()?;
                self.emit("GetGlobalObject", vec![reg(global)]);
                self.emit_put_by_id(global, value, name.id.sym.as_ref())?;
                self.release_register(global)?;
                self.release_register(value)?;
            }
        }
        Ok(())
    }

    fn compile_expression(&mut self, expression: &Expr) -> Result<u8, Error> {
        match expression {
            Expr::Lit(literal) => self.compile_literal(literal),
            Expr::Ident(identifier) => self.compile_identifier(identifier.sym.as_ref()),
            Expr::Paren(expression) => self.compile_expression(&expression.expr),
            Expr::Seq(sequence) => {
                let Some((last, prefix)) = sequence.exprs.split_last() else {
                    return Err(Error::Unsupported("empty sequence expression".into()));
                };
                for expression in prefix {
                    let result = self.compile_expression(expression)?;
                    self.release_register(result)?;
                }
                self.compile_expression(last)
            }
            Expr::Unary(expression) => self.compile_unary(expression.op, &expression.arg),
            Expr::Bin(expression) => {
                let opcode = binary_opcode(expression.op).ok_or_else(|| {
                    Error::Unsupported(format!(
                        "binary operator `{}` is not supported by native compilation yet",
                        expression.op
                    ))
                })?;
                let left = self.compile_expression(&expression.left)?;
                let right = self.compile_expression(&expression.right)?;
                self.emit(opcode, vec![reg(left), reg(left), reg(right)]);
                self.release_register(right)?;
                Ok(left)
            }
            Expr::Member(member) => self.compile_member_read(member),
            Expr::Assign(assignment) if assignment.op == AssignOp::Assign => {
                self.compile_assignment(&assignment.left, &assignment.right)
            }
            Expr::Assign(assignment) => Err(Error::Unsupported(format!(
                "assignment operator `{}` is not supported by native compilation yet",
                assignment.op
            ))),
            Expr::Call(call) => self.compile_call(call),
            other => Err(unsupported_expression(other)),
        }
    }

    fn compile_literal(&mut self, literal: &Lit) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        match literal {
            Lit::Null(_) => self.emit("LoadConstNull", vec![reg(output)]),
            Lit::Bool(value) => self.emit(
                if value.value {
                    "LoadConstTrue"
                } else {
                    "LoadConstFalse"
                },
                vec![reg(output)],
            ),
            Lit::Num(number) => self.emit_number(output, number.value),
            Lit::Str(string) => {
                let value = string.value.as_str().ok_or_else(|| {
                    Error::Unsupported(
                        "string literals containing lone UTF-16 surrogates are not supported by native compilation yet"
                            .into(),
                    )
                })?;
                let id = self.intern_string(value)?;
                self.emit_load_string(output, id);
            }
            _ => {
                self.release_register(output)?;
                return Err(Error::Unsupported(
                    "this literal kind is not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(output)
    }

    fn emit_number(&mut self, output: u8, value: f64) {
        if value == 0.0 && value.is_sign_positive() {
            self.emit("LoadConstZero", vec![reg(output)]);
        } else if value.fract() == 0.0 && (0.0..=255.0).contains(&value) {
            self.emit(
                "LoadConstUInt8",
                vec![reg(output), DecodedOperand::U8(value as u8)],
            );
        } else if value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64 {
            self.emit(
                "LoadConstInt",
                vec![reg(output), DecodedOperand::I32(value as i32)],
            );
        } else {
            self.emit(
                "LoadConstDouble",
                vec![reg(output), DecodedOperand::F64(value)],
            );
        }
    }

    fn compile_identifier(&mut self, name: &str) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        self.emit("GetGlobalObject", vec![reg(output)]);
        self.emit_get_by_id(output, output, name, true)?;
        Ok(output)
    }

    fn compile_unary(&mut self, operator: UnaryOp, argument: &Expr) -> Result<u8, Error> {
        if operator == UnaryOp::TypeOf
            && let Expr::Ident(identifier) = argument
        {
            let value = self.alloc_register()?;
            self.emit("GetGlobalObject", vec![reg(value)]);
            self.emit_get_by_id(value, value, identifier.sym.as_ref(), false)?;
            self.emit("TypeOf", vec![reg(value), reg(value)]);
            return Ok(value);
        }
        let value = self.compile_expression(argument)?;
        let opcode = match operator {
            UnaryOp::Minus => "Negate",
            UnaryOp::Plus => "ToNumber",
            UnaryOp::Bang => "Not",
            UnaryOp::Tilde => "BitNot",
            UnaryOp::TypeOf => "TypeOf",
            UnaryOp::Void => {
                self.emit("LoadConstUndefined", vec![reg(value)]);
                return Ok(value);
            }
            UnaryOp::Delete => {
                return Err(Error::Unsupported(
                    "delete expressions are not supported by native compilation yet".into(),
                ));
            }
        };
        self.emit(opcode, vec![reg(value), reg(value)]);
        Ok(value)
    }

    fn compile_member_read(&mut self, member: &MemberExpr) -> Result<u8, Error> {
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                self.emit_get_by_id(object, object, property.sym.as_ref(), false)?;
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                self.emit("GetByVal", vec![reg(object), reg(object), reg(key)]);
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private properties are not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(object)
    }

    fn compile_assignment(&mut self, target: &AssignTarget, value: &Expr) -> Result<u8, Error> {
        let AssignTarget::Simple(target) = target else {
            return Err(Error::Unsupported(
                "destructuring assignment is not supported by native compilation yet".into(),
            ));
        };
        match target {
            SimpleAssignTarget::Ident(identifier) => {
                let value = self.compile_expression(value)?;
                let global = self.alloc_register()?;
                self.emit("GetGlobalObject", vec![reg(global)]);
                self.emit_put_by_id(global, value, identifier.id.sym.as_ref())?;
                self.release_register(global)?;
                Ok(value)
            }
            SimpleAssignTarget::Member(member) => self.compile_member_assignment(member, value),
            SimpleAssignTarget::Paren(paren) => {
                let nested = AssignTarget::try_from(paren.expr.clone()).map_err(|_| {
                    Error::Unsupported("invalid parenthesized assignment target".into())
                })?;
                self.compile_assignment(&nested, value)
            }
            _ => Err(Error::Unsupported(
                "this assignment target is not supported by native compilation yet".into(),
            )),
        }
    }

    fn compile_member_assignment(
        &mut self,
        member: &MemberExpr,
        value: &Expr,
    ) -> Result<u8, Error> {
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                let value = self.compile_expression(value)?;
                self.emit_put_by_id(object, value, property.sym.as_ref())?;
                self.emit("Mov", vec![reg(object), reg(value)]);
                self.release_register(value)?;
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                let value = self.compile_expression(value)?;
                self.emit("PutByVal", vec![reg(object), reg(key), reg(value)]);
                self.emit("Mov", vec![reg(object), reg(value)]);
                self.release_register(value)?;
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private properties are not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(object)
    }

    fn compile_call(&mut self, call: &swc_core::ecma::ast::CallExpr) -> Result<u8, Error> {
        if call.args.len() > 3 {
            return Err(Error::Unsupported(
                "native compilation currently supports calls with at most three arguments".into(),
            ));
        }
        if call.args.iter().any(|argument| argument.spread.is_some()) {
            return Err(Error::Unsupported(
                "spread call arguments are not supported by native compilation yet".into(),
            ));
        }
        self.max_call_arguments = self
            .max_call_arguments
            .max(u16::try_from(call.args.len() + 1).expect("calls are limited to four operands"));
        let Callee::Expr(callee) = &call.callee else {
            return Err(Error::Unsupported(
                "super and import calls are not supported by native compilation yet".into(),
            ));
        };
        if matches!(&**callee, Expr::Ident(identifier) if identifier.sym == "eval") {
            return Err(Error::Unsupported(
                "direct eval is not supported by native compilation yet".into(),
            ));
        }

        let (result, function, this_value) = if let Expr::Member(member) = &**callee {
            let this_value = self.compile_expression(&member.obj)?;
            let function = self.alloc_register()?;
            match &member.prop {
                MemberProp::Ident(property) => {
                    self.emit_get_by_id(function, this_value, property.sym.as_ref(), false)?;
                }
                MemberProp::Computed(property) => {
                    let key = self.compile_expression(&property.expr)?;
                    self.emit("GetByVal", vec![reg(function), reg(this_value), reg(key)]);
                    self.release_register(key)?;
                }
                MemberProp::PrivateName(_) => {
                    return Err(Error::Unsupported(
                        "private method calls are not supported by native compilation yet".into(),
                    ));
                }
            }
            (this_value, function, this_value)
        } else {
            let function = self.compile_expression(callee)?;
            let this_value = self.alloc_register()?;
            self.emit("LoadConstUndefined", vec![reg(this_value)]);
            (function, function, this_value)
        };

        let mut arguments = Vec::with_capacity(call.args.len());
        for argument in &call.args {
            arguments.push(self.compile_expression(&argument.expr)?);
        }
        let output = self.alloc_register()?;
        let mut operands = vec![reg(output), reg(function), reg(this_value)];
        operands.extend(arguments.iter().copied().map(reg));
        let opcode = match arguments.len() {
            0 => "Call1",
            1 => "Call2",
            2 => "Call3",
            3 => "Call4",
            _ => unreachable!(),
        };
        self.emit(opcode, operands);
        self.emit("Mov", vec![reg(result), reg(output)]);
        self.release_register(output)?;
        while let Some(argument) = arguments.pop() {
            self.release_register(argument)?;
        }
        if function != result {
            self.release_register(function)?;
        } else {
            self.release_register(this_value)?;
        }
        Ok(result)
    }

    fn emit_get_by_id(
        &mut self,
        output: u8,
        object: u8,
        name: &str,
        checked: bool,
    ) -> Result<(), Error> {
        let id = self.intern_identifier(name)?;
        let cache = self.alloc_cache()?;
        let (short, long) = if checked {
            ("TryGetById", "TryGetByIdLong")
        } else {
            ("GetById", "GetByIdLong")
        };
        if let Ok(id) = u16::try_from(id) {
            self.emit(
                short,
                vec![
                    reg(output),
                    reg(object),
                    DecodedOperand::U8(cache),
                    DecodedOperand::U16(id),
                ],
            );
        } else {
            self.emit(
                long,
                vec![
                    reg(output),
                    reg(object),
                    DecodedOperand::U8(cache),
                    DecodedOperand::U32(id),
                ],
            );
        }
        Ok(())
    }

    fn emit_put_by_id(&mut self, object: u8, value: u8, name: &str) -> Result<(), Error> {
        let id = self.intern_identifier(name)?;
        let cache = self.alloc_cache()?;
        if let Ok(id) = u16::try_from(id) {
            self.emit(
                "PutById",
                vec![
                    reg(object),
                    reg(value),
                    DecodedOperand::U8(cache),
                    DecodedOperand::U16(id),
                ],
            );
        } else {
            self.emit(
                "PutByIdLong",
                vec![
                    reg(object),
                    reg(value),
                    DecodedOperand::U8(cache),
                    DecodedOperand::U32(id),
                ],
            );
        }
        Ok(())
    }

    fn emit_load_string(&mut self, output: u8, id: u32) {
        if let Ok(id) = u16::try_from(id) {
            self.emit(
                "LoadConstString",
                vec![reg(output), DecodedOperand::U16(id)],
            );
        } else {
            self.emit(
                "LoadConstStringLongIndex",
                vec![reg(output), DecodedOperand::U32(id)],
            );
        }
    }

    fn intern_identifier(&mut self, value: &str) -> Result<u32, Error> {
        let id = self.intern(value, StringKind::Identifier)?;
        self.string_kinds[id as usize] = StringKind::Identifier;
        Ok(id)
    }

    fn intern_string(&mut self, value: &str) -> Result<u32, Error> {
        self.intern(value, StringKind::String)
    }

    fn intern(&mut self, value: &str, kind: StringKind) -> Result<u32, Error> {
        if let Some(id) = self.string_ids.get(value) {
            return Ok(*id);
        }
        let id = u32::try_from(self.strings.len())
            .map_err(|_| Error::Unsupported("too many strings for HBC 96".into()))?;
        self.strings.push(value.to_owned());
        self.string_kinds.push(kind);
        self.string_ids.insert(value.to_owned(), id);
        Ok(id)
    }

    fn alloc_register(&mut self) -> Result<u8, Error> {
        // Small HBC function headers encode a seven-bit frame size.
        if self.next_register >= 127 {
            return Err(Error::Unsupported(
                "expression needs more than 127 live registers".into(),
            ));
        }
        let register = self.next_register as u8;
        self.next_register += 1;
        self.frame_size = self.frame_size.max(self.next_register);
        Ok(register)
    }

    fn release_register(&mut self, register: u8) -> Result<(), Error> {
        if self.next_register != u16::from(register) + 1 {
            return Err(Error::Bytecode(
                "native compiler register allocation became unbalanced".into(),
            ));
        }
        self.next_register -= 1;
        Ok(())
    }

    fn alloc_cache(&mut self) -> Result<u8, Error> {
        let cache = u8::try_from(self.next_cache).map_err(|_| {
            Error::Unsupported("script needs more than 256 property cache entries".into())
        })?;
        self.next_cache += 1;
        Ok(cache)
    }

    fn emit(&mut self, name: &str, operands: Vec<DecodedOperand>) {
        self.instructions.push(DecodedInstruction {
            offset: 0,
            opcode: 0,
            name: name.into(),
            operands,
            size: 0,
        });
    }
}

fn collect_var_declarations(statements: &[Stmt], names: &mut Vec<String>) -> Result<(), Error> {
    for statement in statements {
        match statement {
            Stmt::Decl(Decl::Var(declaration)) if declaration.kind == VarDeclKind::Var => {
                for declarator in &declaration.decls {
                    let Pat::Ident(identifier) = &declarator.name else {
                        return Err(Error::Unsupported(
                            "destructuring declarations are not supported by native compilation yet"
                                .into(),
                        ));
                    };
                    names.push(identifier.id.sym.to_string());
                }
            }
            Stmt::Block(block) => collect_var_declarations(&block.stmts, names)?,
            _ => {}
        }
    }
    Ok(())
}

fn is_string_expression(statement: &Stmt) -> bool {
    matches!(statement, Stmt::Expr(statement) if matches!(&*statement.expr, Expr::Lit(Lit::Str(_))))
}

fn binary_opcode(operator: BinaryOp) -> Option<&'static str> {
    Some(match operator {
        BinaryOp::EqEq => "Eq",
        BinaryOp::NotEq => "Neq",
        BinaryOp::EqEqEq => "StrictEq",
        BinaryOp::NotEqEq => "StrictNeq",
        BinaryOp::Lt => "Less",
        BinaryOp::LtEq => "LessEq",
        BinaryOp::Gt => "Greater",
        BinaryOp::GtEq => "GreaterEq",
        BinaryOp::LShift => "LShift",
        BinaryOp::RShift => "RShift",
        BinaryOp::ZeroFillRShift => "URshift",
        BinaryOp::Add => "Add",
        BinaryOp::Sub => "Sub",
        BinaryOp::Mul => "Mul",
        BinaryOp::Div => "Div",
        BinaryOp::Mod => "Mod",
        BinaryOp::BitOr => "BitOr",
        BinaryOp::BitXor => "BitXor",
        BinaryOp::BitAnd => "BitAnd",
        BinaryOp::In => "IsIn",
        BinaryOp::InstanceOf => "InstanceOf",
        BinaryOp::LogicalOr
        | BinaryOp::LogicalAnd
        | BinaryOp::Exp
        | BinaryOp::NullishCoalescing => return None,
    })
}

fn reg(value: u8) -> DecodedOperand {
    DecodedOperand::U8(value)
}

fn unsupported_statement(statement: &Stmt) -> Error {
    Error::Unsupported(format!(
        "{} statements are not supported by native compilation yet",
        match statement {
            Stmt::With(_) => "with",
            Stmt::Return(_) => "return",
            Stmt::Labeled(_) => "labeled",
            Stmt::Break(_) => "break",
            Stmt::Continue(_) => "continue",
            Stmt::If(_) => "if",
            Stmt::Switch(_) => "switch",
            Stmt::Throw(_) => "throw",
            Stmt::Try(_) => "try",
            Stmt::While(_) => "while",
            Stmt::DoWhile(_) => "do-while",
            Stmt::For(_) => "for",
            Stmt::ForIn(_) => "for-in",
            Stmt::ForOf(_) => "for-of",
            Stmt::Decl(_) => "this declaration",
            _ => "this",
        }
    ))
}

fn unsupported_expression(expression: &Expr) -> Error {
    Error::Unsupported(format!(
        "{} expressions are not supported by native compilation yet",
        match expression {
            Expr::This(_) => "this",
            Expr::Array(_) => "array",
            Expr::Object(_) => "object",
            Expr::Fn(_) => "function",
            Expr::Arrow(_) => "arrow function",
            Expr::Class(_) => "class",
            Expr::Cond(_) => "conditional",
            Expr::New(_) => "new",
            Expr::Update(_) => "update",
            Expr::Yield(_) => "yield",
            Expr::Await(_) => "await",
            Expr::Tpl(_) | Expr::TaggedTpl(_) => "template literal",
            _ => "this",
        }
    ))
}

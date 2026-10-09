use std::{
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
};

use mercury_binary::{
    DecodedInstruction, DecodedOperand, ExceptionHandlerEntry, HbcString, MinimalFunction,
    MinimalModule, StringKind, build_minimal_module, encode_instruction,
};
use mercury_spec::BytecodeSpec;
use swc_core::ecma::ast::{
    ArrowExpr, AssignOp, AssignTarget, BinaryOp, BlockStmt, BlockStmtOrExpr, Callee, Decl, Expr,
    ForHead, Function, Lit, MemberExpr, MemberProp, MetaPropKind, ObjectPatProp, Pat, Program,
    Prop, PropName, PropOrSpread, Script, SimpleAssignTarget, Stmt, UnaryOp, UpdateOp, VarDecl,
    VarDeclKind, VarDeclOrExpr,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::{Error, SwcModule};

const LEXICAL_THIS_BINDING: &str = "\0mercury_lexical_this";
const LEXICAL_ARGUMENTS_BINDING: &str = "\0mercury_lexical_arguments";
// Hermes 0.12's HBC 96 runtime uses the legacy private-builtin layout.
const SILENT_SET_PROTOTYPE_OF_BUILTIN: u8 = 37;
const THROW_TYPE_ERROR_BUILTIN: u8 = 42;
const COPY_DATA_PROPERTIES_BUILTIN: u8 = 44;
const COPY_REST_ARGS_BUILTIN: u8 = 45;
const ARRAY_SPREAD_BUILTIN: u8 = 46;
const APPLY_BUILTIN: u8 = 47;
const EXPONENTIATION_BUILTIN: u8 = 49;

/// Native SWC-AST to Hermes-bytecode compiler.
///
/// The native compiler targets HBC 96 scripts. Unsupported syntax is
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
    strings: Vec<HbcString>,
    string_kinds: Vec<StringKind>,
    string_ids: HashMap<HbcString, u32>,
    next_register: u16,
    frame_size: u16,
    max_call_arguments: u16,
    next_cache: u16,
    labels: Vec<Option<usize>>,
    branches: Vec<PendingBranch>,
    frame_moves: Vec<PendingFrameMove>,
    exception_handlers: Vec<PendingExceptionHandler>,
    active_exception_regions: Vec<ActiveExceptionRegion>,
    cleanup_stack: Vec<CleanupContext>,
    break_targets: Vec<ControlTarget>,
    continue_targets: Vec<ControlTarget>,
    pending_functions: VecDeque<PendingFunction>,
    next_function_id: u32,
    scope: Option<Rc<FunctionScope>>,
    environment_register: Option<u8>,
    base_registers: u16,
    is_global: bool,
    current_function_id: u32,
    current_function_kind: NativeFunctionKind,
    current_function_strict: bool,
}

#[derive(Clone)]
struct PendingFunction {
    id: u32,
    name: String,
    params: Vec<Pat>,
    body: PendingFunctionBody,
    kind: NativeFunctionKind,
    strict: bool,
    parent_scope: Option<Rc<FunctionScope>>,
}

#[derive(Clone)]
enum PendingFunctionBody {
    Block(BlockStmt),
    Expression(Box<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeFunctionKind {
    Regular,
    Arrow,
}

impl NativeFunctionKind {
    fn prohibit_invoke(self) -> u8 {
        match self {
            Self::Regular => 2,
            Self::Arrow => 1,
        }
    }
}

#[derive(Debug)]
struct FunctionScope {
    bindings: HashMap<String, Binding>,
    parent: Option<Rc<FunctionScope>>,
    function_id: u32,
    environment_register: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingKind {
    Var,
    Parameter,
    Let,
    Const,
}

impl BindingKind {
    fn has_tdz(self) -> bool {
        matches!(self, Self::Parameter | Self::Let | Self::Const)
    }
}

#[derive(Clone, Copy, Debug)]
struct Binding {
    slot: u8,
    kind: BindingKind,
}

#[derive(Clone, Copy)]
enum BindingLocation {
    Local { environment: u8, binding: Binding },
    Parent { level: u8, binding: Binding },
    Global,
}

#[derive(Clone, Copy)]
struct PendingBranch {
    instruction: usize,
    target: usize,
}

#[derive(Clone, Copy)]
struct PendingFrameMove {
    instruction: usize,
    slot: u16,
}

#[derive(Clone, Copy)]
struct PendingExceptionHandler {
    start: usize,
    end: usize,
    target: usize,
}

#[derive(Clone, Copy)]
struct ActiveExceptionRegion {
    start: Option<usize>,
    target: usize,
}

#[derive(Clone)]
struct FinallyContext {
    block: BlockStmt,
    exception_depth: usize,
    scope: Option<Rc<FunctionScope>>,
    environment_register: u8,
}

#[derive(Clone)]
struct IteratorCleanupContext {
    iterator: u8,
    exception_depth: usize,
}

#[derive(Clone)]
enum CleanupContext {
    Finally(FinallyContext),
    Iterator(IteratorCleanupContext),
}

#[derive(Clone, Copy)]
struct ControlTarget {
    label: usize,
    cleanup_depth: usize,
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
            labels: Vec::new(),
            branches: Vec::new(),
            frame_moves: Vec::new(),
            exception_handlers: Vec::new(),
            active_exception_regions: Vec::new(),
            cleanup_stack: Vec::new(),
            break_targets: Vec::new(),
            continue_targets: Vec::new(),
            pending_functions: VecDeque::new(),
            next_function_id: 1,
            scope: None,
            environment_register: None,
            base_registers: 0,
            is_global: true,
            current_function_id: 0,
            current_function_kind: NativeFunctionKind::Regular,
            current_function_strict: false,
        }
    }

    fn compile_script(mut self, script: &Script) -> Result<Vec<u8>, Error> {
        let spec = mercury_spec_builtin::load_spec(self.version)
            .ok_or_else(|| Error::Bytecode("missing embedded HBC 96 spec".into()))?;
        let (directive_count, strict) = directive_prologue(&script.body);
        let mut lexical_bindings = direct_lexical_bindings(&script.body)?;
        let lexical_names = lexical_bindings
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let captures_this = statements_contain_arrow(&script.body);
        if captures_this {
            add_binding(
                &mut lexical_bindings,
                LEXICAL_THIS_BINDING.into(),
                BindingKind::Var,
            )?;
        }
        let global_environment_size = self.begin_function(
            0,
            lexical_bindings,
            None,
            true,
            NativeFunctionKind::Regular,
            strict,
        )?;
        if captures_this {
            self.initialize_lexical_this()?;
        }
        for name in lexical_names {
            let id = self.intern_identifier(&name)?;
            self.emit(
                "ThrowIfHasRestrictedGlobalProperty",
                vec![DecodedOperand::U32(id)],
            );
        }

        let mut declarations = Vec::new();
        collect_var_declarations(&script.body, &mut declarations)?;
        declarations.extend(
            top_level_function_declarations(&script.body)
                .map(|declaration| declaration.ident.sym.to_string()),
        );
        let mut declared = HashSet::new();
        declarations.retain(|name| declared.insert(name.clone()));
        for name in declarations {
            let id = self.intern_identifier(&name)?;
            self.emit("DeclareGlobalVar", vec![DecodedOperand::U32(id)]);
        }

        self.hoist_function_declarations(&script.body)?;

        for statement in &script.body[directive_count..] {
            if !matches!(statement, Stmt::Decl(Decl::Fn(_))) {
                self.compile_statement(statement)?;
            }
            debug_assert_eq!(self.next_register, self.base_registers);
        }

        self.emit_implicit_return()?;
        let global =
            self.finish_function("global".into(), 1, global_environment_size, &spec.bytecode)?;
        let mut functions = vec![global];

        while let Some(pending) = self.pending_functions.pop_front() {
            if pending.id as usize != functions.len() {
                return Err(Error::Bytecode(
                    "native compiler assigned a non-contiguous function id".into(),
                ));
            }
            functions.push(self.compile_pending_function(pending, &spec.bytecode)?);
        }

        let module = MinimalModule {
            version: self.version,
            global_code_index: 0,
            strings: self.strings,
            string_kinds: self.string_kinds,
            literal_value_buffer: Vec::new(),
            object_key_buffer: Vec::new(),
            object_value_buffer: Vec::new(),
            functions,
        };
        build_minimal_module(&module, &spec.bytecode)
            .map_err(|error| Error::Bytecode(error.to_string()))
    }

    fn begin_function(
        &mut self,
        function_id: u32,
        bindings: Vec<(String, BindingKind)>,
        parent_scope: Option<Rc<FunctionScope>>,
        is_global: bool,
        kind: NativeFunctionKind,
        strict: bool,
    ) -> Result<u32, Error> {
        self.instructions.clear();
        self.next_register = 0;
        self.frame_size = 0;
        self.max_call_arguments = 0;
        self.next_cache = 0;
        self.labels.clear();
        self.branches.clear();
        self.frame_moves.clear();
        self.exception_handlers.clear();
        self.active_exception_regions.clear();
        self.cleanup_stack.clear();
        self.break_targets.clear();
        self.continue_targets.clear();
        self.is_global = is_global;
        self.current_function_id = function_id;
        self.current_function_kind = kind;
        self.current_function_strict = strict;
        self.base_registers = 0;
        let mut chunks = bindings.chunks(255);
        let first_bindings = chunks.next().unwrap_or_default().to_vec();
        let environment_size = first_bindings.len() as u32;
        let environment = self.alloc_register()?;
        self.environment_register = Some(environment);
        self.emit("CreateEnvironment", vec![reg(environment)]);
        self.scope = Some(Rc::new(FunctionScope {
            bindings: build_binding_map(first_bindings)?,
            parent: parent_scope,
            function_id,
            environment_register: environment,
        }));
        self.initialize_scope_bindings()?;
        for chunk in chunks {
            let _ = self.enter_lexical_scope(chunk.to_vec())?;
        }
        self.base_registers = self.next_register;
        Ok(environment_size)
    }

    fn initialize_lexical_this(&mut self) -> Result<(), Error> {
        let value = self.alloc_register()?;
        self.emit_this_load(value);
        self.emit_binding_initialization(LEXICAL_THIS_BINDING, value)?;
        self.release_register(value)
    }

    fn emit_this_load(&mut self, output: u8) {
        if self.current_function_strict {
            self.emit(
                "LoadParam",
                vec![reg(output), DecodedOperand::U8(0)],
            );
        } else {
            self.emit("LoadThisNS", vec![reg(output)]);
        }
    }

    fn initialize_scope_bindings(&mut self) -> Result<(), Error> {
        let mut bindings = self
            .current_scope_bindings()?
            .values()
            .copied()
            .collect::<Vec<_>>();
        bindings.sort_by_key(|binding| binding.slot);
        for binding in bindings {
            let value = self.alloc_register()?;
            self.emit(
                if binding.kind.has_tdz() {
                    "LoadConstEmpty"
                } else {
                    "LoadConstUndefined"
                },
                vec![reg(value)],
            );
            let environment = self.environment_register()?;
            self.emit(
                "StoreToEnvironment",
                vec![
                    reg(environment),
                    DecodedOperand::U8(binding.slot),
                    reg(value),
                ],
            );
            self.release_register(value)?;
        }
        Ok(())
    }

    fn current_scope_bindings(&self) -> Result<&HashMap<String, Binding>, Error> {
        self.scope
            .as_ref()
            .map(|scope| &scope.bindings)
            .ok_or_else(|| Error::Bytecode("native compiler has no active lexical scope".into()))
    }

    fn hoist_function_declarations(&mut self, statements: &[Stmt]) -> Result<(), Error> {
        for declaration in top_level_function_declarations(statements) {
            let name = declaration.ident.sym.to_string();
            let function_id = self.register_function(name.clone(), &declaration.function)?;
            let closure = self.emit_create_closure(function_id)?;
            self.emit_identifier_store(&name, closure)?;
            self.release_register(closure)?;
        }
        Ok(())
    }

    fn register_function(&mut self, name: String, function: &Function) -> Result<u32, Error> {
        if function.is_async || function.is_generator {
            return Err(Error::Unsupported(
                "async and generator source functions are not supported by native compilation yet"
                    .into(),
            ));
        }
        let body = function.body.clone().ok_or_else(|| {
            Error::Unsupported("function declarations without bodies are not supported".into())
        })?;
        let strict = self.current_function_strict || directive_prologue(&body.stmts).1;
        self.register_pending_function(
            name,
            function
                .params
                .iter()
                .map(|parameter| parameter.pat.clone())
                .collect(),
            PendingFunctionBody::Block(body),
            NativeFunctionKind::Regular,
            strict,
        )
    }

    fn register_accessor(
        &mut self,
        name: String,
        params: Vec<Pat>,
        body: &Option<BlockStmt>,
    ) -> Result<u32, Error> {
        let body = body.clone().ok_or_else(|| {
            Error::Unsupported("object accessors without bodies are not supported".into())
        })?;
        let strict = self.current_function_strict || directive_prologue(&body.stmts).1;
        self.register_pending_function(
            name,
            params,
            PendingFunctionBody::Block(body),
            NativeFunctionKind::Regular,
            strict,
        )
    }

    fn register_arrow(&mut self, arrow: &ArrowExpr) -> Result<u32, Error> {
        if arrow.is_async || arrow.is_generator {
            return Err(Error::Unsupported(
                "async and generator arrow functions are not supported by native compilation yet"
                    .into(),
            ));
        }
        let body = match &*arrow.body {
            BlockStmtOrExpr::BlockStmt(body) => PendingFunctionBody::Block(body.clone()),
            BlockStmtOrExpr::Expr(expression) => {
                PendingFunctionBody::Expression(expression.clone())
            }
        };
        let strict = self.current_function_strict
            || match &body {
                PendingFunctionBody::Block(block) => directive_prologue(&block.stmts).1,
                PendingFunctionBody::Expression(_) => false,
            };
        self.register_pending_function(
            String::new(),
            arrow.params.clone(),
            body,
            NativeFunctionKind::Arrow,
            strict,
        )
    }

    fn register_pending_function(
        &mut self,
        name: String,
        params: Vec<Pat>,
        body: PendingFunctionBody,
        kind: NativeFunctionKind,
        strict: bool,
    ) -> Result<u32, Error> {
        let id = self.next_function_id;
        self.next_function_id = self
            .next_function_id
            .checked_add(1)
            .ok_or_else(|| Error::Unsupported("too many functions for HBC 96".into()))?;
        self.pending_functions.push_back(PendingFunction {
            id,
            name,
            params,
            body,
            kind,
            strict,
            parent_scope: self.scope.clone(),
        });
        Ok(id)
    }

    fn emit_create_closure(&mut self, function_id: u32) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        let environment = self.environment_register()?;
        if let Ok(function_id) = u16::try_from(function_id) {
            self.emit(
                "CreateClosure",
                vec![
                    reg(output),
                    reg(environment),
                    DecodedOperand::U16(function_id),
                ],
            );
        } else {
            self.emit(
                "CreateClosureLongIndex",
                vec![
                    reg(output),
                    reg(environment),
                    DecodedOperand::U32(function_id),
                ],
            );
        }
        Ok(output)
    }

    fn compile_pending_function(
        &mut self,
        pending: PendingFunction,
        spec: &BytecodeSpec,
    ) -> Result<MinimalFunction, Error> {
        let param_count = u32::try_from(pending.params.len() + 1)
            .map_err(|_| Error::Unsupported("too many function parameters".into()))?;
        if param_count >= 128 {
            return Err(Error::Unsupported(
                "functions with more than 126 parameters do not fit an HBC 96 small header".into(),
            ));
        }

        let mut parameter_bindings = Vec::new();
        let simple_parameters = pending
            .params
            .iter()
            .all(|parameter| matches!(parameter, Pat::Ident(_)));
        let parameter_kind = if simple_parameters {
            BindingKind::Var
        } else {
            BindingKind::Parameter
        };
        for parameter in &pending.params {
            collect_pattern_bindings(parameter, parameter_kind, &mut parameter_bindings)?;
        }
        let mut body_bindings = Vec::new();
        let block = match &pending.body {
            PendingFunctionBody::Block(block) => Some(block),
            PendingFunctionBody::Expression(_) => None,
        };
        if let Some(body) = block {
            let mut var_names = Vec::new();
            collect_var_declarations(&body.stmts, &mut var_names)?;
            for name in var_names {
                add_binding(&mut body_bindings, name, BindingKind::Var)?;
            }
            for declaration in top_level_function_declarations(&body.stmts) {
                add_binding(
                    &mut body_bindings,
                    declaration.ident.sym.to_string(),
                    BindingKind::Var,
                )?;
            }
            for (name, kind) in direct_lexical_bindings(&body.stmts)? {
                add_binding(&mut body_bindings, name, kind)?;
            }
        }
        let arguments_is_shadowed = pending
            .params
            .iter()
            .any(|parameter| pattern_binds(parameter, "arguments"));
        let has_implicit_arguments =
            pending.kind == NativeFunctionKind::Regular && !arguments_is_shadowed;
        if has_implicit_arguments {
            if simple_parameters {
                body_bindings
                    .retain(|(name, kind)| name != "arguments" || *kind != BindingKind::Var);
            }
            add_binding(
                &mut parameter_bindings,
                LEXICAL_ARGUMENTS_BINDING.into(),
                BindingKind::Var,
            )?;
        }
        let captures_this = pending.kind == NativeFunctionKind::Regular
            && (pending_body_contains_arrow(&pending.body)
                || patterns_contain_arrow(&pending.params));
        if captures_this {
            add_binding(
                &mut parameter_bindings,
                LEXICAL_THIS_BINDING.into(),
                BindingKind::Var,
            )?;
        }
        if simple_parameters {
            for (name, kind) in body_bindings.drain(..) {
                add_binding(&mut parameter_bindings, name, kind)?;
            }
        }
        let environment_size = self.begin_function(
            pending.id,
            parameter_bindings,
            pending.parent_scope,
            false,
            pending.kind,
            pending.strict,
        )?;
        if has_implicit_arguments {
            self.initialize_implicit_arguments()?;
        }
        if captures_this {
            self.initialize_lexical_this()?;
        }
        for (index, parameter) in pending.params.iter().enumerate() {
            if let Pat::Rest(rest) = parameter {
                if index + 1 != pending.params.len() {
                    return Err(Error::Unsupported(
                        "a rest parameter must be the final parameter".into(),
                    ));
                }
                let start = self.alloc_register()?;
                self.emit_number(start, index as f64);
                let value = self.emit_builtin_call(COPY_REST_ARGS_BUILTIN, &[start])?;
                self.compile_pattern_initialization(&rest.arg, value)?;
                self.release_register(value)?;
                self.release_register(start)?;
            } else {
                let value = self.alloc_register()?;
                let parameter_index = u8::try_from(index + 1).map_err(|_| {
                    Error::Unsupported("function parameter index exceeds HBC 96".into())
                })?;
                self.emit(
                    "LoadParam",
                    vec![reg(value), DecodedOperand::U8(parameter_index)],
                );
                self.compile_pattern_initialization(parameter, value)?;
                self.release_register(value)?;
            }
        }
        if !simple_parameters && !body_bindings.is_empty() {
            self.enter_function_body_scope(body_bindings)?;
        }
        match &pending.body {
            PendingFunctionBody::Block(body) => {
                self.hoist_function_declarations(&body.stmts)?;
                let (directive_count, _) = directive_prologue(&body.stmts);
                for statement in &body.stmts[directive_count..] {
                    if !matches!(statement, Stmt::Decl(Decl::Fn(_))) {
                        self.compile_statement(statement)?;
                    }
                    debug_assert_eq!(self.next_register, self.base_registers);
                }
            }
            PendingFunctionBody::Expression(expression) => {
                let value = self.compile_expression(expression)?;
                self.emit("Ret", vec![reg(value)]);
                self.release_register(value)?;
            }
        }
        self.emit_implicit_return()?;
        self.finish_function(pending.name, param_count, environment_size, spec)
    }

    fn enter_function_body_scope(
        &mut self,
        bindings: Vec<(String, BindingKind)>,
    ) -> Result<(), Error> {
        let outer_scope = self
            .scope
            .clone()
            .ok_or_else(|| Error::Bytecode("native compiler has no parameter scope".into()))?;
        let outer_environment = self.environment_register()?;
        let copies = bindings
            .iter()
            .filter_map(|(name, kind)| {
                if *kind != BindingKind::Var {
                    return None;
                }
                let source = outer_scope.bindings.get(name).copied().or_else(|| {
                    (name == "arguments")
                        .then(|| outer_scope.bindings.get(LEXICAL_ARGUMENTS_BINDING).copied())
                        .flatten()
                });
                source.map(|binding| (name.clone(), binding))
            })
            .collect::<Vec<_>>();

        // Environment slot operands are eight bits wide. Keep one logical
        // function-body scope as a chain of physical environments when a
        // recovered function contains more bindings than one can hold.
        for chunk in bindings.chunks(255) {
            let _ = self.enter_lexical_scope(chunk.to_vec())?;
        }
        for (name, source) in copies {
            let value = self.alloc_register()?;
            self.emit(
                "LoadFromEnvironment",
                vec![
                    reg(value),
                    reg(outer_environment),
                    DecodedOperand::U8(source.slot),
                ],
            );
            self.emit_binding_initialization(&name, value)?;
            self.release_register(value)?;
        }
        self.base_registers = self.next_register;
        Ok(())
    }

    fn initialize_implicit_arguments(&mut self) -> Result<(), Error> {
        let value = self.alloc_register()?;
        self.emit("LoadConstUndefined", vec![reg(value)]);
        self.emit("ReifyArguments", vec![reg(value)]);
        self.emit_binding_initialization(LEXICAL_ARGUMENTS_BINDING, value)?;
        self.release_register(value)
    }

    fn emit_implicit_return(&mut self) -> Result<(), Error> {
        let result = self.alloc_register()?;
        self.emit("LoadConstUndefined", vec![reg(result)]);
        self.emit("Ret", vec![reg(result)]);
        self.release_register(result)
    }

    fn finish_function(
        &mut self,
        name: String,
        param_count: u32,
        environment_size: u32,
        spec: &BytecodeSpec,
    ) -> Result<MinimalFunction, Error> {
        if !self.active_exception_regions.is_empty() || !self.cleanup_stack.is_empty() {
            return Err(Error::Bytecode(
                "native compiler finished with an active exception context".into(),
            ));
        }
        // Hermes reserves six caller registers plus the largest outgoing
        // argument area (including `this`) at the end of a function frame.
        let frame_size = if self.max_call_arguments == 0 {
            self.frame_size.max(1)
        } else {
            self.frame_size
                .checked_add(6)
                .and_then(|size| size.checked_add(self.max_call_arguments))
                .ok_or_else(|| {
                    Error::Unsupported("script needs an HBC frame larger than u16".into())
                })?
        };
        if frame_size >= 128 {
            return Err(Error::Unsupported(
                "script needs a function frame too large for an HBC 96 small header".into(),
            ));
        }
        self.resolve_frame_moves(frame_size)?;
        self.resolve_branches(spec)?;
        let exception_handlers = self.resolve_exception_handlers()?;
        Ok(MinimalFunction {
            name,
            param_count,
            frame_size: u32::from(frame_size),
            environment_size,
            prohibit_invoke: self.current_function_kind.prohibit_invoke(),
            strict_mode: self.current_function_strict,
            exception_handlers,
            instructions: std::mem::take(&mut self.instructions),
        })
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
            Stmt::Decl(Decl::Fn(_)) => Err(Error::Unsupported(
                "function declarations inside blocks are not supported by native compilation yet"
                    .into(),
            )),
            Stmt::Return(statement) => {
                if self.is_global {
                    return Err(Error::Unsupported("return outside a function".into()));
                }
                let value = if let Some(argument) = &statement.arg {
                    self.compile_expression(argument)?
                } else {
                    let value = self.alloc_register()?;
                    self.emit("LoadConstUndefined", vec![reg(value)]);
                    value
                };
                self.compile_cleanups_to_depth(0)?;
                self.emit("Ret", vec![reg(value)]);
                self.release_register(value)
            }
            Stmt::If(statement) => self.compile_if(statement),
            Stmt::While(statement) => self.compile_while(statement),
            Stmt::DoWhile(statement) => self.compile_do_while(statement),
            Stmt::For(statement) => self.compile_for(statement),
            Stmt::ForIn(statement) => self.compile_for_in(statement),
            Stmt::ForOf(statement) => self.compile_for_of(statement),
            Stmt::Switch(statement) => self.compile_switch(statement),
            Stmt::Try(statement) => self.compile_try(statement),
            Stmt::Throw(statement) => {
                let value = self.compile_expression(&statement.arg)?;
                self.emit("Throw", vec![reg(value)]);
                self.release_register(value)
            }
            Stmt::Break(statement) => {
                if statement.label.is_some() {
                    return Err(Error::Unsupported(
                        "labeled break is not supported by native compilation yet".into(),
                    ));
                }
                let target = self
                    .break_targets
                    .last()
                    .copied()
                    .ok_or_else(|| Error::Unsupported("break outside a loop or switch".into()))?;
                self.compile_cleanups_to_depth(target.cleanup_depth)?;
                self.emit_branch("JmpLong", target.label, None);
                Ok(())
            }
            Stmt::Continue(statement) => {
                if statement.label.is_some() {
                    return Err(Error::Unsupported(
                        "labeled continue is not supported by native compilation yet".into(),
                    ));
                }
                let target = self
                    .continue_targets
                    .last()
                    .copied()
                    .ok_or_else(|| Error::Unsupported("continue outside a loop".into()))?;
                self.compile_cleanups_to_depth(target.cleanup_depth)?;
                self.emit_branch("JmpLong", target.label, None);
                Ok(())
            }
            other => Err(unsupported_statement(other)),
        }
    }

    fn compile_block(&mut self, block: &BlockStmt) -> Result<(), Error> {
        let bindings = direct_lexical_bindings(&block.stmts)?;
        if bindings.is_empty() {
            for statement in &block.stmts {
                self.compile_statement(statement)?;
            }
            return Ok(());
        }

        let (previous_scope, previous_environment, environment) =
            self.enter_lexical_scope(bindings)?;
        for statement in &block.stmts {
            self.compile_statement(statement)?;
        }
        self.leave_lexical_scope(previous_scope, previous_environment, environment)
    }

    fn enter_lexical_scope(
        &mut self,
        bindings: Vec<(String, BindingKind)>,
    ) -> Result<(Option<Rc<FunctionScope>>, u8, u8), Error> {
        let previous_scope = self.scope.clone();
        let previous_environment = self.environment_register()?;
        let slot_count = u32::try_from(bindings.len())
            .map_err(|_| Error::Unsupported("too many lexical bindings".into()))?;
        if slot_count >= 256 {
            return Err(Error::Unsupported(
                "lexical scopes with more than 255 bindings are not supported".into(),
            ));
        }
        let environment = self.alloc_register()?;
        self.emit(
            "CreateInnerEnvironment",
            vec![
                reg(environment),
                reg(previous_environment),
                DecodedOperand::U32(slot_count),
            ],
        );
        self.scope = Some(Rc::new(FunctionScope {
            bindings: build_binding_map(bindings)?,
            parent: previous_scope.clone(),
            function_id: self.current_function_id,
            environment_register: environment,
        }));
        self.environment_register = Some(environment);
        self.initialize_scope_bindings()?;
        Ok((previous_scope, previous_environment, environment))
    }

    fn leave_lexical_scope(
        &mut self,
        previous_scope: Option<Rc<FunctionScope>>,
        previous_environment: u8,
        environment: u8,
    ) -> Result<(), Error> {
        self.scope = previous_scope;
        self.environment_register = Some(previous_environment);
        self.release_register(environment)
    }

    fn compile_if(&mut self, statement: &swc_core::ecma::ast::IfStmt) -> Result<(), Error> {
        let alternative = self.new_label();
        let end = statement.alt.as_ref().map(|_| self.new_label());
        let test = self.compile_expression(&statement.test)?;
        self.emit_branch("JmpFalseLong", alternative, Some(test));
        self.release_register(test)?;
        self.compile_statement(&statement.cons)?;
        if let Some(end) = end {
            self.emit_branch("JmpLong", end, None);
        }
        self.mark_label(alternative)?;
        if let Some(alternative) = &statement.alt {
            self.compile_statement(alternative)?;
            self.mark_label(end.expect("alternative has an end label"))?;
        }
        Ok(())
    }

    fn compile_while(&mut self, statement: &swc_core::ecma::ast::WhileStmt) -> Result<(), Error> {
        let condition = self.new_label();
        let end = self.new_label();
        self.mark_label(condition)?;
        let test = self.compile_expression(&statement.test)?;
        self.emit_branch("JmpFalseLong", end, Some(test));
        self.release_register(test)?;
        let cleanup_depth = self.cleanup_stack.len();
        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth,
        });
        self.continue_targets.push(ControlTarget {
            label: condition,
            cleanup_depth,
        });
        self.compile_statement(&statement.body)?;
        self.continue_targets.pop();
        self.break_targets.pop();
        self.emit_branch("JmpLong", condition, None);
        self.mark_label(end)
    }

    fn compile_do_while(
        &mut self,
        statement: &swc_core::ecma::ast::DoWhileStmt,
    ) -> Result<(), Error> {
        let body = self.new_label();
        let condition = self.new_label();
        let end = self.new_label();
        self.mark_label(body)?;
        let cleanup_depth = self.cleanup_stack.len();
        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth,
        });
        self.continue_targets.push(ControlTarget {
            label: condition,
            cleanup_depth,
        });
        self.compile_statement(&statement.body)?;
        self.continue_targets.pop();
        self.break_targets.pop();
        self.mark_label(condition)?;
        let test = self.compile_expression(&statement.test)?;
        self.emit_branch("JmpTrueLong", body, Some(test));
        self.release_register(test)?;
        self.mark_label(end)
    }

    fn compile_for(&mut self, statement: &swc_core::ecma::ast::ForStmt) -> Result<(), Error> {
        if let Some(VarDeclOrExpr::VarDecl(declaration)) = &statement.init
            && declaration.kind != VarDeclKind::Var
        {
            let bindings = declaration_bindings(declaration)?;
            let (previous_scope, parent_environment, iteration_environment) =
                self.enter_lexical_scope(bindings)?;
            self.compile_var_declaration(declaration)?;
            let iteration_bindings = self.sorted_current_bindings()?;
            self.compile_for_loop(
                statement,
                Some((
                    parent_environment,
                    iteration_environment,
                    &iteration_bindings,
                )),
            )?;
            return self.leave_lexical_scope(
                previous_scope,
                parent_environment,
                iteration_environment,
            );
        }

        if let Some(initializer) = &statement.init {
            match initializer {
                VarDeclOrExpr::VarDecl(declaration) => {
                    self.compile_var_declaration(declaration)?;
                }
                VarDeclOrExpr::Expr(expression) => {
                    let value = self.compile_expression(expression)?;
                    self.release_register(value)?;
                }
            }
        }
        self.compile_for_loop(statement, None)
    }

    fn compile_for_loop(
        &mut self,
        statement: &swc_core::ecma::ast::ForStmt,
        iteration_scope: Option<(u8, u8, &[Binding])>,
    ) -> Result<(), Error> {
        let condition = self.new_label();
        let update = self.new_label();
        let end = self.new_label();
        self.mark_label(condition)?;
        if let Some(test) = &statement.test {
            let value = self.compile_expression(test)?;
            self.emit_branch("JmpFalseLong", end, Some(value));
            self.release_register(value)?;
        }
        let cleanup_depth = self.cleanup_stack.len();
        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth,
        });
        self.continue_targets.push(ControlTarget {
            label: update,
            cleanup_depth,
        });
        self.compile_statement(&statement.body)?;
        self.continue_targets.pop();
        self.break_targets.pop();
        self.mark_label(update)?;
        if let Some((parent_environment, iteration_environment, bindings)) = iteration_scope {
            self.clone_iteration_environment(parent_environment, iteration_environment, bindings)?;
        }
        if let Some(update) = &statement.update {
            let value = self.compile_expression(update)?;
            self.release_register(value)?;
        }
        self.emit_branch("JmpLong", condition, None);
        self.mark_label(end)
    }

    fn compile_for_in(
        &mut self,
        statement: &swc_core::ecma::ast::ForInStmt,
    ) -> Result<(), Error> {
        let lexical_bindings = match &statement.left {
            ForHead::VarDecl(declaration) if declaration.kind != VarDeclKind::Var => {
                Some(declaration_bindings(declaration)?)
            }
            _ => None,
        };
        if let ForHead::VarDecl(declaration) = &statement.left
            && (declaration.decls.len() != 1 || declaration.decls[0].init.is_some())
        {
            return Err(Error::Unsupported(
                "for-in declarations require one uninitialized binding".into(),
            ));
        }

        // The right-hand expression is evaluated before a lexical loop binding
        // enters scope.
        let object = self.compile_expression(&statement.right)?;
        let lexical_scope = if let Some(bindings) = lexical_bindings {
            let (previous_scope, parent_environment, iteration_environment) =
                self.enter_lexical_scope(bindings)?;
            let iteration_bindings = self.sorted_current_bindings()?;
            Some((
                previous_scope,
                parent_environment,
                iteration_environment,
                iteration_bindings,
            ))
        } else {
            None
        };

        let list = self.alloc_register()?;
        let index = self.alloc_register()?;
        let size = self.alloc_register()?;
        let property = self.alloc_register()?;
        let next = self.new_label();
        let advance = self.new_label();
        let end = self.new_label();

        self.emit(
            "GetPNameList",
            vec![reg(list), reg(object), reg(index), reg(size)],
        );
        self.emit_branch("JmpUndefinedLong", end, Some(list));
        self.mark_label(next)?;
        self.emit(
            "GetNextPName",
            vec![reg(property), reg(list), reg(object), reg(index), reg(size)],
        );
        self.emit_branch("JmpUndefinedLong", end, Some(property));
        self.compile_for_iteration_head(&statement.left, property)?;

        let cleanup_depth = self.cleanup_stack.len();
        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth,
        });
        self.continue_targets.push(ControlTarget {
            label: advance,
            cleanup_depth,
        });
        self.compile_statement(&statement.body)?;
        self.continue_targets.pop();
        self.break_targets.pop();

        self.mark_label(advance)?;
        if let Some((_, parent_environment, iteration_environment, bindings)) = &lexical_scope {
            self.reset_iteration_environment(
                *parent_environment,
                *iteration_environment,
                bindings,
            )?;
        }
        self.emit_branch("JmpLong", next, None);
        self.mark_label(end)?;

        self.release_register(property)?;
        self.release_register(size)?;
        self.release_register(index)?;
        self.release_register(list)?;
        if let Some((previous_scope, parent_environment, iteration_environment, _)) = lexical_scope {
            self.leave_lexical_scope(
                previous_scope,
                parent_environment,
                iteration_environment,
            )?;
        }
        self.release_register(object)
    }

    fn compile_for_iteration_head(&mut self, head: &ForHead, value: u8) -> Result<(), Error> {
        match head {
            ForHead::VarDecl(declaration) => {
                self.compile_pattern_initialization(&declaration.decls[0].name, value)
            }
            ForHead::Pat(pattern) => self.compile_assignment_pattern(pattern, value),
            ForHead::UsingDecl(_) => Err(Error::Unsupported(
                "using declarations in iteration loops are not supported by native compilation yet"
                    .into(),
            )),
        }
    }

    fn compile_for_of(
        &mut self,
        statement: &swc_core::ecma::ast::ForOfStmt,
    ) -> Result<(), Error> {
        if statement.is_await {
            return Err(Error::Unsupported(
                "for-await-of statements are not supported by native compilation yet".into(),
            ));
        }
        let lexical_bindings = match &statement.left {
            ForHead::VarDecl(declaration) if declaration.kind != VarDeclKind::Var => {
                Some(declaration_bindings(declaration)?)
            }
            _ => None,
        };
        if let ForHead::VarDecl(declaration) = &statement.left
            && (declaration.decls.len() != 1 || declaration.decls[0].init.is_some())
        {
            return Err(Error::Unsupported(
                "for-of declarations require one uninitialized binding".into(),
            ));
        }

        let source = self.compile_expression(&statement.right)?;
        let lexical_scope = if let Some(bindings) = lexical_bindings {
            let (previous_scope, parent_environment, iteration_environment) =
                self.enter_lexical_scope(bindings)?;
            let iteration_bindings = self.sorted_current_bindings()?;
            Some((
                previous_scope,
                parent_environment,
                iteration_environment,
                iteration_bindings,
            ))
        } else {
            None
        };

        let iterator = self.alloc_register()?;
        let value = self.alloc_register()?;
        self.emit("IteratorBegin", vec![reg(iterator), reg(source)]);

        let next = self.new_label();
        let advance = self.new_label();
        let close_on_exception = self.new_label();
        let end = self.new_label();
        self.mark_label(next)?;
        self.emit(
            "IteratorNext",
            vec![reg(value), reg(iterator), reg(source)],
        );
        self.emit_branch("JmpUndefinedLong", end, Some(iterator));

        let exception_depth = self.active_exception_regions.len();
        self.begin_exception_region(close_on_exception)?;
        let outer_cleanup_depth = self.cleanup_stack.len();
        self.cleanup_stack
            .push(CleanupContext::Iterator(IteratorCleanupContext {
                iterator,
                exception_depth,
            }));
        self.compile_for_iteration_head(&statement.left, value)?;

        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth: outer_cleanup_depth,
        });
        self.continue_targets.push(ControlTarget {
            label: advance,
            cleanup_depth: self.cleanup_stack.len(),
        });
        self.compile_statement(&statement.body)?;
        self.continue_targets.pop();
        self.break_targets.pop();
        let cleanup = self
            .cleanup_stack
            .pop()
            .ok_or_else(|| Error::Bytecode("missing iterator cleanup context".into()))?;
        if !matches!(cleanup, CleanupContext::Iterator(_)) {
            return Err(Error::Bytecode("invalid iterator cleanup context".into()));
        }
        self.end_exception_region()?;

        self.mark_label(advance)?;
        if let Some((_, parent_environment, iteration_environment, bindings)) = &lexical_scope {
            self.reset_iteration_environment(
                *parent_environment,
                *iteration_environment,
                bindings,
            )?;
        }
        self.emit_branch("JmpLong", next, None);

        self.mark_label(close_on_exception)?;
        let exception = self.alloc_register()?;
        self.emit("Catch", vec![reg(exception)]);
        self.emit(
            "IteratorClose",
            vec![reg(iterator), DecodedOperand::U8(1)],
        );
        self.emit("Throw", vec![reg(exception)]);
        self.release_register(exception)?;

        self.mark_label(end)?;
        self.release_register(value)?;
        self.release_register(iterator)?;
        if let Some((previous_scope, parent_environment, iteration_environment, _)) = lexical_scope {
            self.leave_lexical_scope(
                previous_scope,
                parent_environment,
                iteration_environment,
            )?;
        }
        self.release_register(source)
    }

    fn compile_assignment_pattern(&mut self, pattern: &Pat, value: u8) -> Result<(), Error> {
        match pattern {
            Pat::Ident(identifier) => self.emit_identifier_store(identifier.id.sym.as_ref(), value),
            Pat::Expr(expression) => self.compile_assignment_target_value(expression, value),
            _ => Err(Error::Unsupported(
                "destructuring iteration assignment targets are not supported by native compilation yet"
                    .into(),
            )),
        }
    }

    fn compile_assignment_target_value(&mut self, target: &Expr, value: u8) -> Result<(), Error> {
        match target {
            Expr::Ident(identifier) => self.emit_identifier_store(identifier.sym.as_ref(), value),
            Expr::Member(member) => {
                let object = self.compile_expression(&member.obj)?;
                match &member.prop {
                    MemberProp::Ident(property) => {
                        self.emit_put_by_id(object, value, property.sym.as_ref())?;
                    }
                    MemberProp::Computed(property) => {
                        let key = self.compile_expression(&property.expr)?;
                        self.emit("PutByVal", vec![reg(object), reg(key), reg(value)]);
                        self.release_register(key)?;
                    }
                    MemberProp::PrivateName(_) => {
                        return Err(Error::Unsupported(
                            "private iteration targets are not supported by native compilation yet"
                                .into(),
                        ));
                    }
                }
                self.release_register(object)
            }
            Expr::Paren(parenthesized) => {
                self.compile_assignment_target_value(&parenthesized.expr, value)
            }
            _ => Err(Error::Unsupported(
                "this iteration assignment target is not supported by native compilation yet"
                    .into(),
            )),
        }
    }

    fn compile_switch(&mut self, statement: &swc_core::ecma::ast::SwitchStmt) -> Result<(), Error> {
        let discriminant = self.compile_expression(&statement.discriminant)?;
        let labels = statement
            .cases
            .iter()
            .map(|_| self.new_label())
            .collect::<Vec<_>>();
        let end = self.new_label();
        let default = statement
            .cases
            .iter()
            .position(|case| case.test.is_none())
            .map_or(end, |index| labels[index]);

        for (case, label) in statement.cases.iter().zip(labels.iter().copied()) {
            let Some(test) = &case.test else {
                continue;
            };
            let comparison = self.compile_expression(test)?;
            self.emit(
                "StrictEq",
                vec![reg(comparison), reg(discriminant), reg(comparison)],
            );
            self.emit_branch("JmpTrueLong", label, Some(comparison));
            self.release_register(comparison)?;
        }
        self.release_register(discriminant)?;
        self.emit_branch("JmpLong", default, None);

        self.break_targets.push(ControlTarget {
            label: end,
            cleanup_depth: self.cleanup_stack.len(),
        });
        for (case, label) in statement.cases.iter().zip(labels) {
            self.mark_label(label)?;
            for consequent in &case.cons {
                self.compile_statement(consequent)?;
            }
        }
        self.break_targets.pop();
        self.mark_label(end)
    }

    fn compile_try(&mut self, statement: &swc_core::ecma::ast::TryStmt) -> Result<(), Error> {
        let after = self.new_label();
        let catch_target = statement.handler.as_ref().map(|_| self.new_label());
        let exceptional_finally = statement.finalizer.as_ref().map(|_| self.new_label());
        let normal_finally = statement.finalizer.as_ref().map(|_| self.new_label());
        let exception_depth = self.active_exception_regions.len();
        let finally_context = statement
            .finalizer
            .as_ref()
            .map(|block| -> Result<FinallyContext, Error> {
                Ok(FinallyContext {
                    block: block.clone(),
                    exception_depth,
                    scope: self.scope.clone(),
                    environment_register: self.environment_register()?,
                })
            })
            .transpose()?;
        if let Some(context) = &finally_context {
            self.cleanup_stack
                .push(CleanupContext::Finally(context.clone()));
        }

        let try_handler = catch_target
            .or(exceptional_finally)
            .ok_or_else(|| Error::Bytecode("try statement has no handler or finalizer".into()))?;
        self.begin_exception_region(try_handler)?;
        self.compile_block(&statement.block)?;
        self.end_exception_region()?;
        self.emit_branch("JmpLong", normal_finally.unwrap_or(after), None);

        if let (Some(target), Some(handler)) = (catch_target, &statement.handler) {
            self.mark_label(target)?;
            let exception = self.alloc_register()?;
            self.emit("Catch", vec![reg(exception)]);
            if let Some(target) = exceptional_finally {
                self.begin_exception_region(target)?;
            }
            self.compile_catch_clause(handler, exception)?;
            if exceptional_finally.is_some() {
                self.end_exception_region()?;
            }
            self.release_register(exception)?;
            self.emit_branch("JmpLong", normal_finally.unwrap_or(after), None);
        }

        if let Some(context) = finally_context {
            let popped = self
                .cleanup_stack
                .pop()
                .ok_or_else(|| Error::Bytecode("missing finally context".into()))?;
            let CleanupContext::Finally(popped) = popped else {
                return Err(Error::Bytecode("invalid finally cleanup context".into()));
            };
            debug_assert_eq!(popped.exception_depth, context.exception_depth);

            self.mark_label(normal_finally.expect("finally has a normal target"))?;
            self.compile_finally_context(&context, self.cleanup_stack.len())?;
            self.emit_branch("JmpLong", after, None);

            self.mark_label(exceptional_finally.expect("finally has an exception target"))?;
            let exception = self.alloc_register()?;
            self.emit("Catch", vec![reg(exception)]);
            self.compile_finally_context(&context, self.cleanup_stack.len())?;
            self.emit("Throw", vec![reg(exception)]);
            self.release_register(exception)?;
        }

        self.mark_label(after)
    }

    fn compile_catch_clause(
        &mut self,
        handler: &swc_core::ecma::ast::CatchClause,
        exception: u8,
    ) -> Result<(), Error> {
        let Some(parameter) = &handler.param else {
            return self.compile_block(&handler.body);
        };
        let mut bindings = Vec::new();
        collect_pattern_bindings(parameter, BindingKind::Let, &mut bindings)?;
        for (name, kind) in direct_lexical_bindings(&handler.body.stmts)? {
            add_binding(&mut bindings, name, kind)?;
        }
        let (previous_scope, previous_environment, environment) =
            self.enter_lexical_scope(bindings)?;
        self.compile_pattern_initialization(parameter, exception)?;
        for statement in &handler.body.stmts {
            self.compile_statement(statement)?;
        }
        self.leave_lexical_scope(previous_scope, previous_environment, environment)
    }

    fn begin_exception_region(&mut self, target: usize) -> Result<(), Error> {
        let start = self.new_label();
        self.mark_label(start)?;
        self.active_exception_regions.push(ActiveExceptionRegion {
            start: Some(start),
            target,
        });
        Ok(())
    }

    fn end_exception_region(&mut self) -> Result<(), Error> {
        let region = self
            .active_exception_regions
            .pop()
            .ok_or_else(|| Error::Bytecode("missing active exception region".into()))?;
        if let Some(start) = region.start {
            let end = self.new_label();
            self.mark_label(end)?;
            self.push_exception_segment(start, end, region.target)?;
        }
        Ok(())
    }

    fn pause_exception_regions(&mut self, depth: usize) -> Result<Vec<usize>, Error> {
        if depth > self.active_exception_regions.len() {
            return Err(Error::Bytecode("invalid exception-region depth".into()));
        }
        let paused = (depth..self.active_exception_regions.len())
            .filter(|index| self.active_exception_regions[*index].start.is_some())
            .collect::<Vec<_>>();
        if paused.is_empty() {
            return Ok(paused);
        }
        let end = self.new_label();
        self.mark_label(end)?;
        for index in paused.iter().rev().copied() {
            let region = &mut self.active_exception_regions[index];
            let start = region.start.take().expect("selected active region");
            let target = region.target;
            self.push_exception_segment(start, end, target)?;
        }
        Ok(paused)
    }

    fn resume_exception_regions(&mut self, paused: &[usize]) -> Result<(), Error> {
        if paused.is_empty() {
            return Ok(());
        }
        let start = self.new_label();
        self.mark_label(start)?;
        for index in paused {
            self.active_exception_regions[*index].start = Some(start);
        }
        Ok(())
    }

    fn push_exception_segment(
        &mut self,
        start: usize,
        end: usize,
        target: usize,
    ) -> Result<(), Error> {
        let start_position = self
            .labels
            .get(start)
            .and_then(|position| *position)
            .ok_or_else(|| Error::Bytecode("exception segment has no start".into()))?;
        let end_position = self
            .labels
            .get(end)
            .and_then(|position| *position)
            .ok_or_else(|| Error::Bytecode("exception segment has no end".into()))?;
        if start_position < end_position {
            self.exception_handlers.push(PendingExceptionHandler {
                start,
                end,
                target,
            });
        }
        Ok(())
    }

    fn compile_cleanups_to_depth(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.cleanup_stack.len() {
            return Err(Error::Bytecode("invalid cleanup depth".into()));
        }
        let contexts = self.cleanup_stack.clone();
        for index in (depth..contexts.len()).rev() {
            self.compile_cleanup_context(&contexts[index], index)?;
        }
        self.cleanup_stack = contexts;
        Ok(())
    }

    fn compile_cleanup_context(
        &mut self,
        context: &CleanupContext,
        outer_cleanup_depth: usize,
    ) -> Result<(), Error> {
        match context {
            CleanupContext::Finally(context) => {
                self.compile_finally_context(context, outer_cleanup_depth)
            }
            CleanupContext::Iterator(context) => {
                let paused = self.pause_exception_regions(context.exception_depth)?;
                self.emit(
                    "IteratorClose",
                    vec![reg(context.iterator), DecodedOperand::U8(0)],
                );
                self.resume_exception_regions(&paused)
            }
        }
    }

    fn compile_finally_context(
        &mut self,
        context: &FinallyContext,
        outer_cleanup_depth: usize,
    ) -> Result<(), Error> {
        let paused = self.pause_exception_regions(context.exception_depth)?;
        let saved_scope = self.scope.clone();
        let saved_environment = self.environment_register;
        let saved_cleanups = self.cleanup_stack.clone();
        self.scope = context.scope.clone();
        self.environment_register = Some(context.environment_register);
        self.cleanup_stack.truncate(outer_cleanup_depth);
        let result = self.compile_block(&context.block);
        self.scope = saved_scope;
        self.environment_register = saved_environment;
        self.cleanup_stack = saved_cleanups;
        result?;
        self.resume_exception_regions(&paused)
    }

    fn sorted_current_bindings(&self) -> Result<Vec<Binding>, Error> {
        let mut bindings = self
            .current_scope_bindings()?
            .values()
            .copied()
            .collect::<Vec<_>>();
        bindings.sort_by_key(|binding| binding.slot);
        Ok(bindings)
    }

    fn clone_iteration_environment(
        &mut self,
        parent_environment: u8,
        iteration_environment: u8,
        bindings: &[Binding],
    ) -> Result<(), Error> {
        let next_environment = self.alloc_register()?;
        self.emit(
            "CreateInnerEnvironment",
            vec![
                reg(next_environment),
                reg(parent_environment),
                DecodedOperand::U32(bindings.len() as u32),
            ],
        );
        for binding in bindings {
            let value = self.alloc_register()?;
            self.emit(
                "LoadFromEnvironment",
                vec![
                    reg(value),
                    reg(iteration_environment),
                    DecodedOperand::U8(binding.slot),
                ],
            );
            self.emit(
                "StoreToEnvironment",
                vec![
                    reg(next_environment),
                    DecodedOperand::U8(binding.slot),
                    reg(value),
                ],
            );
            self.release_register(value)?;
        }
        self.emit(
            "Mov",
            vec![reg(iteration_environment), reg(next_environment)],
        );
        self.release_register(next_environment)
    }

    fn reset_iteration_environment(
        &mut self,
        parent_environment: u8,
        iteration_environment: u8,
        bindings: &[Binding],
    ) -> Result<(), Error> {
        let next_environment = self.alloc_register()?;
        self.emit(
            "CreateInnerEnvironment",
            vec![
                reg(next_environment),
                reg(parent_environment),
                DecodedOperand::U32(bindings.len() as u32),
            ],
        );
        for binding in bindings {
            let empty = self.alloc_register()?;
            self.emit("LoadConstEmpty", vec![reg(empty)]);
            self.emit(
                "StoreToEnvironment",
                vec![
                    reg(next_environment),
                    DecodedOperand::U8(binding.slot),
                    reg(empty),
                ],
            );
            self.release_register(empty)?;
        }
        self.emit(
            "Mov",
            vec![reg(iteration_environment), reg(next_environment)],
        );
        self.release_register(next_environment)
    }

    fn compile_var_declaration(&mut self, declaration: &VarDecl) -> Result<(), Error> {
        for declarator in &declaration.decls {
            if let Some(initializer) = &declarator.init {
                let value = self.compile_expression(initializer)?;
                self.compile_pattern_initialization(&declarator.name, value)?;
                self.release_register(value)?;
            } else if declaration.kind == VarDeclKind::Let {
                let value = self.alloc_register()?;
                self.emit("LoadConstUndefined", vec![reg(value)]);
                self.compile_pattern_initialization(&declarator.name, value)?;
                self.release_register(value)?;
            }
        }
        Ok(())
    }

    fn compile_pattern_initialization(&mut self, pattern: &Pat, value: u8) -> Result<(), Error> {
        match pattern {
            Pat::Ident(identifier) => {
                self.emit_binding_initialization(identifier.id.sym.as_ref(), value)
            }
            Pat::Assign(assignment) => {
                let use_default = self.new_label();
                let initialize = self.new_label();
                self.emit_branch("JmpUndefinedLong", use_default, Some(value));
                self.emit_branch("JmpLong", initialize, None);
                self.mark_label(use_default)?;
                let default = self.compile_expression(&assignment.right)?;
                self.emit("Mov", vec![reg(value), reg(default)]);
                self.release_register(default)?;
                self.mark_label(initialize)?;
                self.compile_pattern_initialization(&assignment.left, value)
            }
            Pat::Array(array) => self.compile_array_pattern(array, value),
            Pat::Object(object) => self.compile_object_pattern(object, value),
            Pat::Rest(rest) => self.compile_pattern_initialization(&rest.arg, value),
            Pat::Expr(_) | Pat::Invalid(_) => Err(Error::Unsupported(
                "this binding pattern is not supported by native compilation".into(),
            )),
        }
    }

    fn compile_array_pattern(
        &mut self,
        pattern: &swc_core::ecma::ast::ArrayPat,
        value: u8,
    ) -> Result<(), Error> {
        let array = self.emit_array_from(value)?;
        for (index, element) in pattern.elems.iter().enumerate() {
            let Some(element) = element else {
                continue;
            };
            if let Pat::Rest(rest) = element {
                let tail = self.emit_array_slice(array, index)?;
                self.compile_pattern_initialization(&rest.arg, tail)?;
                self.release_register(tail)?;
                continue;
            }
            let item = self.alloc_register()?;
            self.emit_number(item, index as f64);
            self.emit("GetByVal", vec![reg(item), reg(array), reg(item)]);
            self.compile_pattern_initialization(element, item)?;
            self.release_register(item)?;
        }
        self.release_register(array)
    }

    fn emit_array_from(&mut self, value: u8) -> Result<u8, Error> {
        self.max_call_arguments = self.max_call_arguments.max(2);
        let constructor = self.alloc_register()?;
        self.emit("GetGlobalObject", vec![reg(constructor)]);
        self.emit_get_by_id(constructor, constructor, "Array", true)?;
        let method = self.alloc_register()?;
        self.emit_get_by_id(method, constructor, "from", false)?;
        let output = self.alloc_register()?;
        self.emit(
            "Call2",
            vec![reg(output), reg(method), reg(constructor), reg(value)],
        );
        self.emit("Mov", vec![reg(constructor), reg(output)]);
        self.release_register(output)?;
        self.release_register(method)?;
        Ok(constructor)
    }

    fn emit_array_slice(&mut self, array: u8, start_index: usize) -> Result<u8, Error> {
        self.max_call_arguments = self.max_call_arguments.max(2);
        let method = self.alloc_register()?;
        self.emit_get_by_id(method, array, "slice", false)?;
        let start = self.alloc_register()?;
        self.emit_number(start, start_index as f64);
        let output = self.alloc_register()?;
        self.emit(
            "Call2",
            vec![reg(output), reg(method), reg(array), reg(start)],
        );
        self.emit("Mov", vec![reg(method), reg(output)]);
        self.release_register(output)?;
        self.release_register(start)?;
        Ok(method)
    }

    fn compile_object_pattern(
        &mut self,
        pattern: &swc_core::ecma::ast::ObjectPat,
        value: u8,
    ) -> Result<(), Error> {
        self.emit_require_object_coercible(value)?;

        let has_rest = pattern
            .props
            .iter()
            .any(|property| matches!(property, ObjectPatProp::Rest(_)));
        let excluded = if has_rest {
            let object = self.alloc_register()?;
            self.emit("NewObject", vec![reg(object)]);
            Some(object)
        } else {
            None
        };

        for property in &pattern.props {
            match property {
                ObjectPatProp::KeyValue(property) => {
                    let key = self.compile_property_name(&property.key)?;
                    if let Some(excluded) = excluded {
                        self.emit_excluded_property(excluded, key)?;
                    }
                    self.emit("GetByVal", vec![reg(key), reg(value), reg(key)]);
                    self.compile_pattern_initialization(&property.value, key)?;
                    self.release_register(key)?;
                }
                ObjectPatProp::Assign(property) => {
                    let key = self.compile_string_value(property.key.sym.as_ref())?;
                    if let Some(excluded) = excluded {
                        self.emit_excluded_property(excluded, key)?;
                    }
                    self.emit("GetByVal", vec![reg(key), reg(value), reg(key)]);
                    if let Some(default) = &property.value {
                        let use_default = self.new_label();
                        let initialize = self.new_label();
                        self.emit_branch("JmpUndefinedLong", use_default, Some(key));
                        self.emit_branch("JmpLong", initialize, None);
                        self.mark_label(use_default)?;
                        let default = self.compile_expression(default)?;
                        self.emit("Mov", vec![reg(key), reg(default)]);
                        self.release_register(default)?;
                        self.mark_label(initialize)?;
                    }
                    self.emit_binding_initialization(property.key.sym.as_ref(), key)?;
                    self.release_register(key)?;
                }
                ObjectPatProp::Rest(rest) => {
                    let target = self.alloc_register()?;
                    self.emit("NewObject", vec![reg(target)]);
                    let excluded = excluded.expect("object rest allocated an exclusion object");
                    let rest_value = self.emit_builtin_call(
                        COPY_DATA_PROPERTIES_BUILTIN,
                        &[target, value, excluded],
                    )?;
                    self.compile_pattern_initialization(&rest.arg, rest_value)?;
                    self.release_register(rest_value)?;
                    self.release_register(target)?;
                }
            }
        }
        if let Some(excluded) = excluded {
            self.release_register(excluded)?;
        }
        Ok(())
    }

    fn emit_require_object_coercible(&mut self, value: u8) -> Result<(), Error> {
        let nullish = self.alloc_register()?;
        self.emit("LoadConstNull", vec![reg(nullish)]);
        self.emit("Eq", vec![reg(nullish), reg(nullish), reg(value)]);
        let valid = self.new_label();
        self.emit_branch("JmpFalseLong", valid, Some(nullish));
        let message = self.compile_string_value("Cannot destructure 'undefined' or 'null'.")?;
        let thrown = self.emit_builtin_call(THROW_TYPE_ERROR_BUILTIN, &[message])?;
        self.release_register(thrown)?;
        self.release_register(message)?;
        self.mark_label(valid)?;
        self.release_register(nullish)
    }

    fn emit_excluded_property(&mut self, excluded: u8, key: u8) -> Result<(), Error> {
        let zero = self.alloc_register()?;
        self.emit("LoadConstZero", vec![reg(zero)]);
        self.emit_define_own(excluded, zero, key);
        self.release_register(zero)
    }

    fn emit_builtin_call(&mut self, builtin: u8, arguments: &[u8]) -> Result<u8, Error> {
        let argument_count = u8::try_from(arguments.len() + 1)
            .map_err(|_| Error::Unsupported("too many builtin arguments".into()))?;
        self.max_call_arguments = self.max_call_arguments.max(u16::from(argument_count));
        for (index, argument) in arguments.iter().enumerate() {
            self.emit_frame_move(*argument, (index + 1) as u16);
        }
        let output = self.alloc_register()?;
        self.emit(
            "CallBuiltin",
            vec![
                reg(output),
                DecodedOperand::U8(builtin),
                DecodedOperand::U8(argument_count),
            ],
        );
        Ok(output)
    }

    fn emit_binary_operation(
        &mut self,
        operator: BinaryOp,
        left: u8,
        right: u8,
    ) -> Result<(), Error> {
        if operator == BinaryOp::Exp {
            let output = self.emit_builtin_call(EXPONENTIATION_BUILTIN, &[left, right])?;
            self.emit("Mov", vec![reg(left), reg(output)]);
            return self.release_register(output);
        }
        let opcode = binary_opcode(operator).ok_or_else(|| {
            Error::Unsupported(format!(
                "binary operator `{operator}` is not supported by native compilation yet"
            ))
        })?;
        self.emit(opcode, vec![reg(left), reg(left), reg(right)]);
        Ok(())
    }

    fn compile_expression(&mut self, expression: &Expr) -> Result<u8, Error> {
        match expression {
            Expr::Lit(literal) => self.compile_literal(literal),
            Expr::Array(array) => self.compile_array(array),
            Expr::Object(object) => self.compile_object(object),
            Expr::This(_) => {
                if self.current_function_kind == NativeFunctionKind::Arrow {
                    return self.compile_identifier(LEXICAL_THIS_BINDING);
                }
                let output = self.alloc_register()?;
                self.emit_this_load(output);
                Ok(output)
            }
            Expr::MetaProp(property) if property.kind == MetaPropKind::NewTarget => {
                let output = self.alloc_register()?;
                self.emit("GetNewTarget", vec![reg(output)]);
                Ok(output)
            }
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
            Expr::Cond(expression) => {
                self.compile_conditional(&expression.test, &expression.cons, &expression.alt)
            }
            Expr::Bin(expression)
                if matches!(
                    expression.op,
                    BinaryOp::LogicalAnd | BinaryOp::LogicalOr | BinaryOp::NullishCoalescing
                ) =>
            {
                self.compile_short_circuit(expression.op, &expression.left, &expression.right)
            }
            Expr::Bin(expression) => {
                let left = self.compile_expression(&expression.left)?;
                let right = self.compile_expression(&expression.right)?;
                self.emit_binary_operation(expression.op, left, right)?;
                self.release_register(right)?;
                Ok(left)
            }
            Expr::Member(member) => self.compile_member_read(member),
            Expr::Assign(assignment) if assignment.op == AssignOp::Assign => {
                self.compile_assignment(&assignment.left, &assignment.right)
            }
            Expr::Assign(assignment) => {
                self.compile_compound_assignment(assignment.op, &assignment.left, &assignment.right)
            }
            Expr::Update(update) => self.compile_update(update.op, update.prefix, &update.arg),
            Expr::Call(call) => self.compile_call(call),
            Expr::New(expression) => self.compile_new(expression),
            Expr::Fn(function) => {
                let name = function
                    .ident
                    .as_ref()
                    .map(|identifier| identifier.sym.to_string())
                    .unwrap_or_default();
                let function_id = self.register_function(name, &function.function)?;
                self.emit_create_closure(function_id)
            }
            Expr::Arrow(arrow) => {
                let function_id = self.register_arrow(arrow)?;
                self.emit_create_closure(function_id)
            }
            other => Err(unsupported_expression(other)),
        }
    }

    fn compile_array(&mut self, array: &swc_core::ecma::ast::ArrayLit) -> Result<u8, Error> {
        if array
            .elems
            .iter()
            .flatten()
            .any(|element| element.spread.is_some())
        {
            let output = self.alloc_register()?;
            self.emit("NewArray", vec![reg(output), DecodedOperand::U16(0)]);
            let next_index = self.alloc_register()?;
            self.emit("LoadConstZero", vec![reg(next_index)]);
            for element in &array.elems {
                if let Some(element) = element {
                    let value = self.compile_expression(&element.expr)?;
                    if element.spread.is_some() {
                        let updated = self.emit_builtin_call(
                            ARRAY_SPREAD_BUILTIN,
                            &[output, value, next_index],
                        )?;
                        self.emit("Mov", vec![reg(next_index), reg(updated)]);
                        self.release_register(updated)?;
                    } else {
                        self.emit_define_own(output, value, next_index);
                        self.emit("Inc", vec![reg(next_index), reg(next_index)]);
                    }
                    self.release_register(value)?;
                } else {
                    self.emit("Inc", vec![reg(next_index), reg(next_index)]);
                }
            }
            self.emit_put_by_id(output, next_index, "length")?;
            self.release_register(next_index)?;
            return Ok(output);
        }

        let length = u16::try_from(array.elems.len()).map_err(|_| {
            Error::Unsupported("array literals with more than 65535 slots are not supported".into())
        })?;
        let output = self.alloc_register()?;
        self.emit("NewArray", vec![reg(output), DecodedOperand::U16(length)]);
        for (index, element) in array.elems.iter().enumerate() {
            let Some(element) = element else {
                continue;
            };
            let value = self.compile_expression(&element.expr)?;
            if let Ok(index) = u8::try_from(index) {
                self.emit(
                    "PutOwnByIndex",
                    vec![reg(output), reg(value), DecodedOperand::U8(index)],
                );
            } else {
                self.emit(
                    "PutOwnByIndexL",
                    vec![reg(output), reg(value), DecodedOperand::U32(index as u32)],
                );
            }
            self.release_register(value)?;
        }
        Ok(output)
    }

    fn compile_object(&mut self, object: &swc_core::ecma::ast::ObjectLit) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        self.emit("NewObject", vec![reg(output)]);
        for property in &object.props {
            let PropOrSpread::Prop(property) = property else {
                let PropOrSpread::Spread(spread) = property else {
                    unreachable!();
                };
                let source = self.compile_expression(&spread.expr)?;
                let copied =
                    self.emit_builtin_call(COPY_DATA_PROPERTIES_BUILTIN, &[output, source])?;
                self.release_register(copied)?;
                self.release_register(source)?;
                continue;
            };
            match &**property {
                Prop::Shorthand(identifier) => {
                    let key = self.compile_string_value(identifier.sym.as_ref())?;
                    let value = self.compile_identifier(identifier.sym.as_ref())?;
                    self.emit_define_own(output, value, key);
                    self.release_register(value)?;
                    self.release_register(key)?;
                }
                Prop::KeyValue(property) => {
                    if is_proto_setter_name(&property.key) {
                        let parent = self.compile_expression(&property.value)?;
                        let updated = self.emit_builtin_call(
                            SILENT_SET_PROTOTYPE_OF_BUILTIN,
                            &[output, parent],
                        )?;
                        self.release_register(updated)?;
                        self.release_register(parent)?;
                        continue;
                    }
                    let key = self.compile_property_name(&property.key)?;
                    let value = self.compile_expression(&property.value)?;
                    self.emit_define_own(output, value, key);
                    self.release_register(value)?;
                    self.release_register(key)?;
                }
                Prop::Method(method) => {
                    let key = self.compile_property_name(&method.key)?;
                    let name = property_function_name(&method.key, "");
                    let function_id = self.register_function(name, &method.function)?;
                    let value = self.emit_create_closure(function_id)?;
                    self.emit_define_own(output, value, key);
                    self.release_register(value)?;
                    self.release_register(key)?;
                }
                Prop::Getter(getter) => {
                    let key = self.compile_property_name(&getter.key)?;
                    let name = property_function_name(&getter.key, "get ");
                    let function_id = self.register_accessor(name, Vec::new(), &getter.body)?;
                    let value = self.emit_create_closure(function_id)?;
                    self.emit_define_accessor(output, key, Some(value), None)?;
                    self.release_register(value)?;
                    self.release_register(key)?;
                }
                Prop::Setter(setter) => {
                    let key = self.compile_property_name(&setter.key)?;
                    let name = property_function_name(&setter.key, "set ");
                    let function_id = self.register_accessor(
                        name,
                        vec![(*setter.param).clone()],
                        &setter.body,
                    )?;
                    let value = self.emit_create_closure(function_id)?;
                    self.emit_define_accessor(output, key, None, Some(value))?;
                    self.release_register(value)?;
                    self.release_register(key)?;
                }
                Prop::Assign(_) => {
                    return Err(Error::Unsupported(
                        "assignment properties are not valid in object literals".into(),
                    ));
                }
            }
        }
        Ok(output)
    }

    fn compile_property_name(&mut self, name: &PropName) -> Result<u8, Error> {
        match name {
            PropName::Ident(identifier) => self.compile_string_value(identifier.sym.as_ref()),
            PropName::Str(string) => {
                let value = match string.value.as_str() {
                    Some(value) => HbcString::from(value),
                    None => HbcString::Utf16(string.value.to_ill_formed_utf16().collect()),
                };
                self.compile_hbc_string_value(value)
            }
            PropName::Num(number) => {
                let output = self.alloc_register()?;
                self.emit_number(output, number.value);
                Ok(output)
            }
            PropName::Computed(property) => self.compile_expression(&property.expr),
            PropName::BigInt(_) => Err(Error::Unsupported(
                "BigInt property names are not supported by native compilation yet".into(),
            )),
        }
    }

    fn compile_string_value(&mut self, value: &str) -> Result<u8, Error> {
        self.compile_hbc_string_value(value.into())
    }

    fn compile_hbc_string_value(&mut self, value: HbcString) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        let id = self.intern(value, StringKind::String)?;
        self.emit_load_string(output, id);
        Ok(output)
    }

    fn emit_define_own(&mut self, object: u8, value: u8, key: u8) {
        self.emit(
            "PutOwnByVal",
            vec![reg(object), reg(value), reg(key), DecodedOperand::U8(1)],
        );
    }

    fn emit_define_accessor(
        &mut self,
        object: u8,
        key: u8,
        getter: Option<u8>,
        setter: Option<u8>,
    ) -> Result<(), Error> {
        let missing = self.alloc_register()?;
        self.emit("LoadConstUndefined", vec![reg(missing)]);
        self.emit(
            "PutOwnGetterSetterByVal",
            vec![
                reg(object),
                reg(key),
                reg(getter.unwrap_or(missing)),
                reg(setter.unwrap_or(missing)),
                DecodedOperand::U8(1),
            ],
        );
        self.release_register(missing)
    }

    fn compile_conditional(
        &mut self,
        test: &Expr,
        consequent: &Expr,
        alternative: &Expr,
    ) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        let alternative_label = self.new_label();
        let end = self.new_label();
        let test = self.compile_expression(test)?;
        self.emit_branch("JmpFalseLong", alternative_label, Some(test));
        self.release_register(test)?;

        let consequent = self.compile_expression(consequent)?;
        self.emit("Mov", vec![reg(output), reg(consequent)]);
        self.release_register(consequent)?;
        self.emit_branch("JmpLong", end, None);

        self.mark_label(alternative_label)?;
        let alternative = self.compile_expression(alternative)?;
        self.emit("Mov", vec![reg(output), reg(alternative)]);
        self.release_register(alternative)?;
        self.mark_label(end)?;
        Ok(output)
    }

    fn compile_short_circuit(
        &mut self,
        operator: BinaryOp,
        left: &Expr,
        right: &Expr,
    ) -> Result<u8, Error> {
        let output = self.compile_expression(left)?;
        let end = self.new_label();
        match operator {
            BinaryOp::LogicalAnd => self.emit_branch("JmpFalseLong", end, Some(output)),
            BinaryOp::LogicalOr => self.emit_branch("JmpTrueLong", end, Some(output)),
            BinaryOp::NullishCoalescing => {
                let evaluate_right = self.new_label();
                self.emit_branch("JmpUndefinedLong", evaluate_right, Some(output));
                let is_null = self.alloc_register()?;
                self.emit("LoadConstNull", vec![reg(is_null)]);
                self.emit("StrictEq", vec![reg(is_null), reg(output), reg(is_null)]);
                self.emit_branch("JmpFalseLong", end, Some(is_null));
                self.release_register(is_null)?;
                self.mark_label(evaluate_right)?;
            }
            _ => unreachable!(),
        }

        let right = self.compile_expression(right)?;
        self.emit("Mov", vec![reg(output), reg(right)]);
        self.release_register(right)?;
        self.mark_label(end)?;
        Ok(output)
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
                let value = match string.value.as_str() {
                    Some(value) => HbcString::from(value),
                    None => HbcString::Utf16(string.value.to_ill_formed_utf16().collect()),
                };
                let id = self.intern(value, StringKind::String)?;
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
        match self.resolve_binding(name)? {
            BindingLocation::Local {
                environment,
                binding,
            } => {
                let output = self.alloc_register()?;
                self.emit(
                    "LoadFromEnvironment",
                    vec![
                        reg(output),
                        reg(environment),
                        DecodedOperand::U8(binding.slot),
                    ],
                );
                self.emit_tdz_check(output, binding.kind);
                Ok(output)
            }
            BindingLocation::Parent { level, binding } => {
                let output = self.alloc_register()?;
                self.emit(
                    "GetEnvironment",
                    vec![reg(output), DecodedOperand::U8(level)],
                );
                self.emit(
                    "LoadFromEnvironment",
                    vec![reg(output), reg(output), DecodedOperand::U8(binding.slot)],
                );
                self.emit_tdz_check(output, binding.kind);
                Ok(output)
            }
            BindingLocation::Global => {
                let output = self.alloc_register()?;
                self.emit("GetGlobalObject", vec![reg(output)]);
                self.emit_get_by_id(output, output, name, true)?;
                Ok(output)
            }
        }
    }

    fn emit_identifier_store(&mut self, name: &str, value: u8) -> Result<(), Error> {
        let location = self.resolve_binding(name)?;
        match location {
            BindingLocation::Local {
                environment,
                binding,
            } => self.emit_checked_environment_store(name, environment, binding, value)?,
            BindingLocation::Parent { level, binding } => {
                let environment = self.alloc_register()?;
                self.emit(
                    "GetEnvironment",
                    vec![reg(environment), DecodedOperand::U8(level)],
                );
                self.emit_checked_environment_store(name, environment, binding, value)?;
                self.release_register(environment)?;
            }
            BindingLocation::Global => {
                let global = self.alloc_register()?;
                self.emit("GetGlobalObject", vec![reg(global)]);
                self.emit_put_by_id(global, value, name)?;
                self.release_register(global)?;
            }
        }
        Ok(())
    }

    fn emit_checked_environment_store(
        &mut self,
        name: &str,
        environment: u8,
        binding: Binding,
        value: u8,
    ) -> Result<(), Error> {
        if binding.kind.has_tdz() {
            let current = self.alloc_register()?;
            self.emit(
                "LoadFromEnvironment",
                vec![
                    reg(current),
                    reg(environment),
                    DecodedOperand::U8(binding.slot),
                ],
            );
            self.emit_tdz_check(current, binding.kind);
            self.release_register(current)?;
        }
        if binding.kind == BindingKind::Const {
            return self.emit_const_assignment_error(name);
        }
        self.emit(
            "StoreToEnvironment",
            vec![
                reg(environment),
                DecodedOperand::U8(binding.slot),
                reg(value),
            ],
        );
        Ok(())
    }

    fn emit_const_assignment_error(&mut self, name: &str) -> Result<(), Error> {
        self.max_call_arguments = self.max_call_arguments.max(2);
        let constructor = self.alloc_register()?;
        self.emit("GetGlobalObject", vec![reg(constructor)]);
        self.emit_get_by_id(constructor, constructor, "TypeError", true)?;

        let receiver = self.alloc_register()?;
        self.emit_get_by_id(receiver, constructor, "prototype", false)?;
        self.emit(
            "CreateThis",
            vec![reg(receiver), reg(receiver), reg(constructor)],
        );
        let message =
            self.compile_string_value(&format!("Assignment to constant variable `{name}`"))?;
        self.emit_frame_move(receiver, 0);
        self.emit_frame_move(message, 1);

        let raw_result = self.alloc_register()?;
        self.emit(
            "Construct",
            vec![reg(raw_result), reg(constructor), DecodedOperand::U8(2)],
        );
        self.emit(
            "SelectObject",
            vec![reg(constructor), reg(receiver), reg(raw_result)],
        );
        self.release_register(raw_result)?;
        self.release_register(message)?;
        self.release_register(receiver)?;
        self.emit("Throw", vec![reg(constructor)]);
        self.release_register(constructor)
    }

    fn emit_binding_initialization(&mut self, name: &str, value: u8) -> Result<(), Error> {
        match self.resolve_binding(name)? {
            BindingLocation::Local {
                environment,
                binding,
            } => self.emit(
                "StoreToEnvironment",
                vec![
                    reg(environment),
                    DecodedOperand::U8(binding.slot),
                    reg(value),
                ],
            ),
            BindingLocation::Parent { level, binding } => {
                let environment = self.alloc_register()?;
                self.emit(
                    "GetEnvironment",
                    vec![reg(environment), DecodedOperand::U8(level)],
                );
                self.emit(
                    "StoreToEnvironment",
                    vec![
                        reg(environment),
                        DecodedOperand::U8(binding.slot),
                        reg(value),
                    ],
                );
                self.release_register(environment)?;
            }
            BindingLocation::Global => {
                let global = self.alloc_register()?;
                self.emit("GetGlobalObject", vec![reg(global)]);
                self.emit_put_by_id(global, value, name)?;
                self.release_register(global)?;
            }
        }
        Ok(())
    }

    fn emit_tdz_check(&mut self, value: u8, kind: BindingKind) {
        if kind.has_tdz() {
            self.emit("ThrowIfEmpty", vec![reg(value), reg(value)]);
        }
    }

    fn resolve_binding(&self, name: &str) -> Result<BindingLocation, Error> {
        if let Some(location) = self.resolve_exact_binding(name)? {
            return Ok(location);
        }
        if name == "arguments"
            && let Some(location) = self.resolve_exact_binding(LEXICAL_ARGUMENTS_BINDING)?
        {
            return Ok(location);
        }
        Ok(BindingLocation::Global)
    }

    fn resolve_exact_binding(&self, name: &str) -> Result<Option<BindingLocation>, Error> {
        let mut current = self.scope.as_ref();
        let mut level = 0u16;
        while let Some(scope) = current {
            if let Some(binding) = scope.bindings.get(name) {
                if scope.function_id == self.current_function_id {
                    return Ok(Some(BindingLocation::Local {
                        environment: scope.environment_register,
                        binding: *binding,
                    }));
                }
                return Ok(Some(BindingLocation::Parent {
                    level: u8::try_from(level).map_err(|_| {
                        Error::Unsupported(
                            "closures nested more than 256 lexical levels are not supported".into(),
                        )
                    })?,
                    binding: *binding,
                }));
            }
            if scope.function_id != self.current_function_id {
                level += 1;
            }
            current = scope.parent.as_ref();
        }
        Ok(None)
    }

    fn environment_register(&self) -> Result<u8, Error> {
        self.environment_register
            .ok_or_else(|| Error::Bytecode("native compiler has no active environment".into()))
    }

    fn compile_unary(&mut self, operator: UnaryOp, argument: &Expr) -> Result<u8, Error> {
        if operator == UnaryOp::Delete {
            return self.compile_delete(argument);
        }
        if operator == UnaryOp::TypeOf
            && let Expr::Ident(identifier) = argument
            && matches!(
                self.resolve_binding(identifier.sym.as_ref())?,
                BindingLocation::Global
            )
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
            UnaryOp::Delete => unreachable!("delete was handled before evaluating its operand"),
        };
        self.emit(opcode, vec![reg(value), reg(value)]);
        Ok(value)
    }

    fn compile_delete(&mut self, argument: &Expr) -> Result<u8, Error> {
        if let Expr::Paren(parenthesized) = argument {
            return self.compile_delete(&parenthesized.expr);
        }
        let Expr::Member(member) = argument else {
            return Err(Error::Unsupported(
                "delete currently requires a property reference".into(),
            ));
        };
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                let id = self.intern_identifier(property.sym.as_ref())?;
                if let Ok(id) = u16::try_from(id) {
                    self.emit(
                        "DelById",
                        vec![reg(object), reg(object), DecodedOperand::U16(id)],
                    );
                } else {
                    self.emit(
                        "DelByIdLong",
                        vec![reg(object), reg(object), DecodedOperand::U32(id)],
                    );
                }
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                self.emit("DelByVal", vec![reg(object), reg(object), reg(key)]);
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private properties cannot be deleted".into(),
                ));
            }
        }
        Ok(object)
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
                self.emit_identifier_store(identifier.id.sym.as_ref(), value)?;
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

    fn compile_compound_assignment(
        &mut self,
        operator: AssignOp,
        target: &AssignTarget,
        right: &Expr,
    ) -> Result<u8, Error> {
        if matches!(
            operator,
            AssignOp::AndAssign | AssignOp::OrAssign | AssignOp::NullishAssign
        ) {
            return self.compile_logical_assignment(operator, target, right);
        }
        let binary = operator.to_update().ok_or_else(|| {
            Error::Unsupported(format!(
                "assignment operator `{operator}` is not supported by native compilation yet"
            ))
        })?;
        let AssignTarget::Simple(target) = target else {
            return Err(Error::Unsupported(
                "destructuring compound assignment is not supported by native compilation yet"
                    .into(),
            ));
        };
        match target {
            SimpleAssignTarget::Ident(identifier) => {
                let current = self.compile_identifier(identifier.id.sym.as_ref())?;
                let right = self.compile_expression(right)?;
                self.emit_binary_operation(binary, current, right)?;
                self.release_register(right)?;
                self.emit_identifier_store(identifier.id.sym.as_ref(), current)?;
                Ok(current)
            }
            SimpleAssignTarget::Member(member) => {
                self.compile_member_compound_assignment(member, binary, right)
            }
            SimpleAssignTarget::Paren(paren) => {
                let nested = AssignTarget::try_from(paren.expr.clone()).map_err(|_| {
                    Error::Unsupported("invalid parenthesized assignment target".into())
                })?;
                self.compile_compound_assignment(operator, &nested, right)
            }
            _ => Err(Error::Unsupported(
                "this compound assignment target is not supported by native compilation yet".into(),
            )),
        }
    }

    fn compile_logical_assignment(
        &mut self,
        operator: AssignOp,
        target: &AssignTarget,
        right: &Expr,
    ) -> Result<u8, Error> {
        let AssignTarget::Simple(target) = target else {
            return Err(Error::Unsupported(
                "destructuring logical assignment is not supported by native compilation yet"
                    .into(),
            ));
        };
        match target {
            SimpleAssignTarget::Ident(identifier) => {
                let current = self.compile_identifier(identifier.id.sym.as_ref())?;
                let end = self.new_label();
                self.emit_logical_assignment_guard(operator, current, end)?;
                let right = self.compile_expression(right)?;
                self.emit_identifier_store(identifier.id.sym.as_ref(), right)?;
                self.emit("Mov", vec![reg(current), reg(right)]);
                self.release_register(right)?;
                self.mark_label(end)?;
                Ok(current)
            }
            SimpleAssignTarget::Member(member) => {
                self.compile_member_logical_assignment(member, operator, right)
            }
            SimpleAssignTarget::Paren(paren) => {
                let nested = AssignTarget::try_from(paren.expr.clone()).map_err(|_| {
                    Error::Unsupported("invalid parenthesized assignment target".into())
                })?;
                self.compile_logical_assignment(operator, &nested, right)
            }
            _ => Err(Error::Unsupported(
                "this logical assignment target is not supported by native compilation yet".into(),
            )),
        }
    }

    fn compile_member_logical_assignment(
        &mut self,
        member: &MemberExpr,
        operator: AssignOp,
        right: &Expr,
    ) -> Result<u8, Error> {
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                let current = self.alloc_register()?;
                self.emit_get_by_id(current, object, property.sym.as_ref(), false)?;
                let end = self.new_label();
                self.emit_logical_assignment_guard(operator, current, end)?;
                let right = self.compile_expression(right)?;
                self.emit_put_by_id(object, right, property.sym.as_ref())?;
                self.emit("Mov", vec![reg(current), reg(right)]);
                self.release_register(right)?;
                self.mark_label(end)?;
                self.emit("Mov", vec![reg(object), reg(current)]);
                self.release_register(current)?;
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                let current = self.alloc_register()?;
                self.emit("GetByVal", vec![reg(current), reg(object), reg(key)]);
                let end = self.new_label();
                self.emit_logical_assignment_guard(operator, current, end)?;
                let right = self.compile_expression(right)?;
                self.emit("PutByVal", vec![reg(object), reg(key), reg(right)]);
                self.emit("Mov", vec![reg(current), reg(right)]);
                self.release_register(right)?;
                self.mark_label(end)?;
                self.emit("Mov", vec![reg(object), reg(current)]);
                self.release_register(current)?;
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private property assignment is not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(object)
    }

    fn emit_logical_assignment_guard(
        &mut self,
        operator: AssignOp,
        current: u8,
        end: usize,
    ) -> Result<(), Error> {
        match operator {
            AssignOp::AndAssign => self.emit_branch("JmpFalseLong", end, Some(current)),
            AssignOp::OrAssign => self.emit_branch("JmpTrueLong", end, Some(current)),
            AssignOp::NullishAssign => {
                let assign = self.new_label();
                self.emit_branch("JmpUndefinedLong", assign, Some(current));
                let is_null = self.alloc_register()?;
                self.emit("LoadConstNull", vec![reg(is_null)]);
                self.emit("StrictEq", vec![reg(is_null), reg(current), reg(is_null)]);
                self.emit_branch("JmpFalseLong", end, Some(is_null));
                self.release_register(is_null)?;
                self.mark_label(assign)?;
            }
            _ => {
                return Err(Error::Bytecode(
                    "native compiler used a non-logical assignment guard".into(),
                ));
            }
        }
        Ok(())
    }

    fn compile_member_compound_assignment(
        &mut self,
        member: &MemberExpr,
        operator: BinaryOp,
        right: &Expr,
    ) -> Result<u8, Error> {
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                let current = self.alloc_register()?;
                self.emit_get_by_id(current, object, property.sym.as_ref(), false)?;
                let right = self.compile_expression(right)?;
                self.emit_binary_operation(operator, current, right)?;
                self.release_register(right)?;
                self.emit_put_by_id(object, current, property.sym.as_ref())?;
                self.emit("Mov", vec![reg(object), reg(current)]);
                self.release_register(current)?;
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                let current = self.alloc_register()?;
                self.emit("GetByVal", vec![reg(current), reg(object), reg(key)]);
                let right = self.compile_expression(right)?;
                self.emit_binary_operation(operator, current, right)?;
                self.release_register(right)?;
                self.emit("PutByVal", vec![reg(object), reg(key), reg(current)]);
                self.emit("Mov", vec![reg(object), reg(current)]);
                self.release_register(current)?;
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private property assignment is not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(object)
    }

    fn compile_update(
        &mut self,
        operator: UpdateOp,
        prefix: bool,
        argument: &Expr,
    ) -> Result<u8, Error> {
        let opcode = match operator {
            UpdateOp::PlusPlus => "Inc",
            UpdateOp::MinusMinus => "Dec",
        };
        match argument {
            Expr::Ident(identifier) => {
                let current = self.compile_identifier(identifier.sym.as_ref())?;
                let updated = self.alloc_register()?;
                self.emit(opcode, vec![reg(updated), reg(current)]);
                self.emit_identifier_store(identifier.sym.as_ref(), updated)?;
                if prefix {
                    self.emit("Mov", vec![reg(current), reg(updated)]);
                }
                self.release_register(updated)?;
                Ok(current)
            }
            Expr::Member(member) => self.compile_member_update(member, opcode, prefix),
            Expr::Paren(paren) => self.compile_update(operator, prefix, &paren.expr),
            _ => Err(Error::Unsupported(
                "this update target is not supported by native compilation yet".into(),
            )),
        }
    }

    fn compile_member_update(
        &mut self,
        member: &MemberExpr,
        opcode: &str,
        prefix: bool,
    ) -> Result<u8, Error> {
        let object = self.compile_expression(&member.obj)?;
        match &member.prop {
            MemberProp::Ident(property) => {
                let current = self.alloc_register()?;
                self.emit_get_by_id(current, object, property.sym.as_ref(), false)?;
                let updated = self.alloc_register()?;
                self.emit(opcode, vec![reg(updated), reg(current)]);
                self.emit_put_by_id(object, updated, property.sym.as_ref())?;
                self.emit(
                    "Mov",
                    vec![reg(object), reg(if prefix { updated } else { current })],
                );
                self.release_register(updated)?;
                self.release_register(current)?;
            }
            MemberProp::Computed(property) => {
                let key = self.compile_expression(&property.expr)?;
                let current = self.alloc_register()?;
                self.emit("GetByVal", vec![reg(current), reg(object), reg(key)]);
                let updated = self.alloc_register()?;
                self.emit(opcode, vec![reg(updated), reg(current)]);
                self.emit("PutByVal", vec![reg(object), reg(key), reg(updated)]);
                self.emit(
                    "Mov",
                    vec![reg(object), reg(if prefix { updated } else { current })],
                );
                self.release_register(updated)?;
                self.release_register(current)?;
                self.release_register(key)?;
            }
            MemberProp::PrivateName(_) => {
                return Err(Error::Unsupported(
                    "private property updates are not supported by native compilation yet".into(),
                ));
            }
        }
        Ok(object)
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

        if call.args.iter().any(|argument| argument.spread.is_some()) {
            let arguments = self.compile_spread_arguments(&call.args)?;
            let output =
                self.emit_builtin_call(APPLY_BUILTIN, &[function, arguments, this_value])?;
            self.emit("Mov", vec![reg(result), reg(output)]);
            self.release_register(output)?;
            self.release_register(arguments)?;
            if function != result {
                self.release_register(function)?;
            } else {
                self.release_register(this_value)?;
            }
            return Ok(result);
        }

        let argument_count = u32::try_from(call.args.len() + 1)
            .map_err(|_| Error::Unsupported("too many call arguments".into()))?;
        self.max_call_arguments = self.max_call_arguments.max(
            u16::try_from(argument_count)
                .map_err(|_| Error::Unsupported("too many call arguments".into()))?,
        );

        let mut arguments = Vec::with_capacity(call.args.len());
        for argument in &call.args {
            arguments.push(self.compile_expression(&argument.expr)?);
        }
        let output = self.alloc_register()?;
        if arguments.len() <= 3 {
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
        } else {
            self.emit_frame_move(this_value, 0);
            for (index, argument) in arguments.iter().enumerate() {
                self.emit_frame_move(
                    *argument,
                    u16::try_from(index + 1)
                        .map_err(|_| Error::Unsupported("too many call arguments".into()))?,
                );
            }
            if let Ok(argument_count) = u8::try_from(argument_count) {
                self.emit(
                    "Call",
                    vec![
                        reg(output),
                        reg(function),
                        DecodedOperand::U8(argument_count),
                    ],
                );
            } else {
                self.emit(
                    "CallLong",
                    vec![
                        reg(output),
                        reg(function),
                        DecodedOperand::U32(argument_count),
                    ],
                );
            }
        }
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

    fn compile_new(&mut self, expression: &swc_core::ecma::ast::NewExpr) -> Result<u8, Error> {
        let arguments = expression.args.as_deref().unwrap_or_default();
        if arguments.iter().any(|argument| argument.spread.is_some()) {
            let constructor = self.compile_expression(&expression.callee)?;
            let arguments = self.compile_spread_arguments(arguments)?;
            let output = self.emit_builtin_call(APPLY_BUILTIN, &[constructor, arguments])?;
            self.emit("Mov", vec![reg(constructor), reg(output)]);
            self.release_register(output)?;
            self.release_register(arguments)?;
            return Ok(constructor);
        }
        let argument_count = u8::try_from(arguments.len() + 1).map_err(|_| {
            Error::Unsupported("constructors with more than 254 arguments are not supported".into())
        })?;
        self.max_call_arguments = self.max_call_arguments.max(u16::from(argument_count));

        let constructor = self.compile_expression(&expression.callee)?;
        let receiver = self.alloc_register()?;
        self.emit_get_by_id(receiver, constructor, "prototype", false)?;
        self.emit(
            "CreateThis",
            vec![reg(receiver), reg(receiver), reg(constructor)],
        );

        let mut values = Vec::with_capacity(arguments.len());
        for argument in arguments {
            values.push(self.compile_expression(&argument.expr)?);
        }
        self.emit_frame_move(receiver, 0);
        for (index, value) in values.iter().enumerate() {
            self.emit_frame_move(
                *value,
                u16::try_from(index + 1).expect("constructor argument count fits u16"),
            );
        }

        let raw_result = self.alloc_register()?;
        self.emit(
            "Construct",
            vec![
                reg(raw_result),
                reg(constructor),
                DecodedOperand::U8(argument_count),
            ],
        );
        self.emit(
            "SelectObject",
            vec![reg(constructor), reg(receiver), reg(raw_result)],
        );
        self.release_register(raw_result)?;
        while let Some(value) = values.pop() {
            self.release_register(value)?;
        }
        self.release_register(receiver)?;
        Ok(constructor)
    }

    fn compile_spread_arguments(
        &mut self,
        arguments: &[swc_core::ecma::ast::ExprOrSpread],
    ) -> Result<u8, Error> {
        let output = self.alloc_register()?;
        self.emit("NewArray", vec![reg(output), DecodedOperand::U16(0)]);
        let next_index = self.alloc_register()?;
        self.emit("LoadConstZero", vec![reg(next_index)]);
        for argument in arguments {
            let value = self.compile_expression(&argument.expr)?;
            if argument.spread.is_some() {
                let updated =
                    self.emit_builtin_call(ARRAY_SPREAD_BUILTIN, &[output, value, next_index])?;
                self.emit("Mov", vec![reg(next_index), reg(updated)]);
                self.release_register(updated)?;
            } else {
                self.emit_define_own(output, value, next_index);
                self.emit("Inc", vec![reg(next_index), reg(next_index)]);
            }
            self.release_register(value)?;
        }
        self.release_register(next_index)?;
        Ok(output)
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
        let id = self.intern(value.into(), StringKind::Identifier)?;
        self.string_kinds[id as usize] = StringKind::Identifier;
        Ok(id)
    }

    fn intern(&mut self, value: HbcString, kind: StringKind) -> Result<u32, Error> {
        if let Some(id) = self.string_ids.get(&value) {
            return Ok(*id);
        }
        let id = u32::try_from(self.strings.len())
            .map_err(|_| Error::Unsupported("too many strings for HBC 96".into()))?;
        self.strings.push(value.clone());
        self.string_kinds.push(kind);
        self.string_ids.insert(value, id);
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
        const PROPERTY_CACHING_DISABLED: u8 = u8::MAX;
        if self.next_cache >= u16::from(PROPERTY_CACHING_DISABLED) {
            return Ok(PROPERTY_CACHING_DISABLED);
        }
        let cache = self.next_cache as u8;
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

    fn new_label(&mut self) -> usize {
        let label = self.labels.len();
        self.labels.push(None);
        label
    }

    fn mark_label(&mut self, label: usize) -> Result<(), Error> {
        let instruction = self.instructions.len();
        let slot = self
            .labels
            .get_mut(label)
            .ok_or_else(|| Error::Bytecode("native compiler referenced an invalid label".into()))?;
        if slot.replace(instruction).is_some() {
            return Err(Error::Bytecode(
                "native compiler defined a label more than once".into(),
            ));
        }
        Ok(())
    }

    fn emit_branch(&mut self, name: &str, target: usize, condition: Option<u8>) {
        let instruction = self.instructions.len();
        let mut operands = vec![DecodedOperand::I32(0)];
        if let Some(condition) = condition {
            operands.push(reg(condition));
        }
        self.emit(name, operands);
        self.branches.push(PendingBranch {
            instruction,
            target,
        });
    }

    fn emit_frame_move(&mut self, source: u8, slot: u16) {
        let instruction = self.instructions.len();
        self.emit("Mov", vec![DecodedOperand::U8(0), reg(source)]);
        self.frame_moves
            .push(PendingFrameMove { instruction, slot });
    }

    fn resolve_frame_moves(&mut self, frame_size: u16) -> Result<(), Error> {
        if self.frame_moves.is_empty() {
            return Ok(());
        }
        let this_register = frame_size.checked_sub(7).ok_or_else(|| {
            Error::Bytecode("native compiler produced an invalid outgoing frame".into())
        })?;
        for pending in &self.frame_moves {
            let destination = this_register.checked_sub(pending.slot).ok_or_else(|| {
                Error::Bytecode("constructor arguments exceed the outgoing frame".into())
            })?;
            self.instructions[pending.instruction].operands[0] =
                DecodedOperand::U8(u8::try_from(destination).map_err(|_| {
                    Error::Bytecode("outgoing register does not fit HBC 96".into())
                })?);
        }
        Ok(())
    }

    fn resolve_branches(&mut self, spec: &BytecodeSpec) -> Result<(), Error> {
        let mut offsets = Vec::with_capacity(self.instructions.len() + 1);
        let mut offset = 0u32;
        for instruction in &self.instructions {
            offsets.push(offset);
            let size = encode_instruction(instruction, spec)
                .map_err(|error| Error::Bytecode(error.to_string()))?
                .len();
            offset = offset
                .checked_add(u32::try_from(size).expect("instruction size fits u32"))
                .ok_or_else(|| Error::Unsupported("function bytecode is too large".into()))?;
        }
        offsets.push(offset);

        for branch in &self.branches {
            let target_instruction = self
                .labels
                .get(branch.target)
                .and_then(|target| *target)
                .ok_or_else(|| Error::Bytecode("native compiler left a label unresolved".into()))?;
            let source = i64::from(offsets[branch.instruction]);
            let target = i64::from(offsets[target_instruction]);
            let displacement = i32::try_from(target - source)
                .map_err(|_| Error::Unsupported("branch displacement exceeds HBC 96".into()))?;
            self.instructions[branch.instruction].operands[0] = DecodedOperand::I32(displacement);
        }

        for (index, instruction) in self.instructions.iter_mut().enumerate() {
            let definition = spec
                .instructions
                .iter()
                .find(|definition| definition.name == instruction.name)
                .ok_or_else(|| {
                    Error::Bytecode(format!(
                        "embedded HBC 96 spec has no {} instruction",
                        instruction.name
                    ))
                })?;
            instruction.offset = offsets[index];
            instruction.opcode = definition.opcode;
            instruction.size = usize::try_from(offsets[index + 1] - offsets[index])
                .expect("instruction size fits usize");
        }
        Ok(())
    }

    fn resolve_exception_handlers(&self) -> Result<Vec<ExceptionHandlerEntry>, Error> {
        let bytecode_end = self
            .instructions
            .last()
            .map(|instruction| instruction.offset + instruction.size as u32)
            .unwrap_or_default();
        let label_offset = |label: usize| -> Result<u32, Error> {
            let instruction = self
                .labels
                .get(label)
                .and_then(|instruction| *instruction)
                .ok_or_else(|| {
                    Error::Bytecode("exception handler has an unresolved label".into())
                })?;
            Ok(self
                .instructions
                .get(instruction)
                .map(|instruction| instruction.offset)
                .unwrap_or(bytecode_end))
        };
        self.exception_handlers
            .iter()
            .map(|handler| {
                Ok(ExceptionHandlerEntry {
                    start: label_offset(handler.start)?,
                    end: label_offset(handler.end)?,
                    target: label_offset(handler.target)?,
                })
            })
            .collect()
    }
}

fn collect_var_declarations(statements: &[Stmt], names: &mut Vec<String>) -> Result<(), Error> {
    for statement in statements {
        collect_statement_var_declarations(statement, names)?;
    }
    Ok(())
}

fn top_level_function_declarations(
    statements: &[Stmt],
) -> impl Iterator<Item = &swc_core::ecma::ast::FnDecl> {
    statements.iter().filter_map(|statement| match statement {
        Stmt::Decl(Decl::Fn(declaration)) => Some(declaration),
        _ => None,
    })
}

#[derive(Default)]
struct ArrowFinder {
    found: bool,
}

impl Visit for ArrowFinder {
    fn visit_arrow_expr(&mut self, _arrow: &ArrowExpr) {
        self.found = true;
    }

    fn visit_function(&mut self, _function: &Function) {}
}

fn statements_contain_arrow(statements: &[Stmt]) -> bool {
    let mut finder = ArrowFinder::default();
    statements.visit_with(&mut finder);
    finder.found
}

fn pending_body_contains_arrow(body: &PendingFunctionBody) -> bool {
    let mut finder = ArrowFinder::default();
    match body {
        PendingFunctionBody::Block(block) => block.visit_with(&mut finder),
        PendingFunctionBody::Expression(expression) => expression.visit_with(&mut finder),
    }
    finder.found
}

fn patterns_contain_arrow(patterns: &[Pat]) -> bool {
    let mut finder = ArrowFinder::default();
    patterns.visit_with(&mut finder);
    finder.found
}

fn pattern_binds(pattern: &Pat, expected: &str) -> bool {
    let mut bindings = Vec::new();
    collect_pattern_bindings(pattern, BindingKind::Var, &mut bindings).is_ok()
        && bindings.iter().any(|(name, _)| name == expected)
}

fn direct_lexical_bindings(statements: &[Stmt]) -> Result<Vec<(String, BindingKind)>, Error> {
    let mut bindings = Vec::new();
    for statement in statements {
        let Stmt::Decl(Decl::Var(declaration)) = statement else {
            continue;
        };
        if declaration.kind == VarDeclKind::Var {
            continue;
        }
        for (name, kind) in declaration_bindings(declaration)? {
            add_binding(&mut bindings, name, kind)?;
        }
    }
    Ok(bindings)
}

fn declaration_bindings(declaration: &VarDecl) -> Result<Vec<(String, BindingKind)>, Error> {
    let kind = match declaration.kind {
        VarDeclKind::Var => BindingKind::Var,
        VarDeclKind::Let => BindingKind::Let,
        VarDeclKind::Const => BindingKind::Const,
    };
    let mut bindings = Vec::new();
    for declarator in &declaration.decls {
        collect_pattern_bindings(&declarator.name, kind, &mut bindings)?;
    }
    Ok(bindings)
}

fn collect_pattern_bindings(
    pattern: &Pat,
    kind: BindingKind,
    bindings: &mut Vec<(String, BindingKind)>,
) -> Result<(), Error> {
    match pattern {
        Pat::Ident(identifier) => {
            add_binding(bindings, identifier.id.sym.to_string(), kind)?;
        }
        Pat::Array(array) => {
            for element in array.elems.iter().flatten() {
                collect_pattern_bindings(element, kind, bindings)?;
            }
        }
        Pat::Object(object) => {
            for property in &object.props {
                match property {
                    ObjectPatProp::KeyValue(property) => {
                        collect_pattern_bindings(&property.value, kind, bindings)?;
                    }
                    ObjectPatProp::Assign(property) => {
                        add_binding(bindings, property.key.sym.to_string(), kind)?;
                    }
                    ObjectPatProp::Rest(property) => {
                        collect_pattern_bindings(&property.arg, kind, bindings)?;
                    }
                }
            }
        }
        Pat::Assign(assignment) => {
            collect_pattern_bindings(&assignment.left, kind, bindings)?;
        }
        Pat::Rest(rest) => collect_pattern_bindings(&rest.arg, kind, bindings)?,
        Pat::Expr(_) | Pat::Invalid(_) => {
            return Err(Error::Unsupported(
                "this binding pattern is not supported by native compilation".into(),
            ));
        }
    }
    Ok(())
}

fn add_binding(
    bindings: &mut Vec<(String, BindingKind)>,
    name: String,
    kind: BindingKind,
) -> Result<(), Error> {
    if let Some((_, existing)) = bindings.iter_mut().find(|(existing, _)| existing == &name) {
        if matches!(
            (*existing, kind),
            (BindingKind::Var, BindingKind::Var)
                | (BindingKind::Parameter, BindingKind::Var)
                | (BindingKind::Var, BindingKind::Parameter)
        ) {
            if kind == BindingKind::Parameter {
                *existing = BindingKind::Parameter;
            }
            return Ok(());
        }
        return Err(Error::Unsupported(format!(
            "conflicting lexical declaration for `{name}`"
        )));
    }
    bindings.push((name, kind));
    Ok(())
}

fn build_binding_map(
    bindings: Vec<(String, BindingKind)>,
) -> Result<HashMap<String, Binding>, Error> {
    if bindings.len() >= 256 {
        return Err(Error::Unsupported(
            "lexical scopes with more than 255 bindings are not supported".into(),
        ));
    }
    Ok(bindings
        .into_iter()
        .enumerate()
        .map(|(slot, (name, kind))| {
            (
                name,
                Binding {
                    slot: slot as u8,
                    kind,
                },
            )
        })
        .collect())
}

fn collect_statement_var_declarations(
    statement: &Stmt,
    names: &mut Vec<String>,
) -> Result<(), Error> {
    match statement {
        Stmt::Decl(Decl::Var(declaration)) if declaration.kind == VarDeclKind::Var => {
            collect_declaration_names(declaration, names)?;
        }
        Stmt::Block(block) => collect_var_declarations(&block.stmts, names)?,
        Stmt::If(statement) => {
            collect_statement_var_declarations(&statement.cons, names)?;
            if let Some(alternative) = &statement.alt {
                collect_statement_var_declarations(alternative, names)?;
            }
        }
        Stmt::While(statement) => collect_statement_var_declarations(&statement.body, names)?,
        Stmt::DoWhile(statement) => collect_statement_var_declarations(&statement.body, names)?,
        Stmt::For(statement) => {
            if let Some(VarDeclOrExpr::VarDecl(declaration)) = &statement.init
                && declaration.kind == VarDeclKind::Var
            {
                collect_declaration_names(declaration, names)?;
            }
            collect_statement_var_declarations(&statement.body, names)?;
        }
        Stmt::ForIn(statement) => {
            if let ForHead::VarDecl(declaration) = &statement.left
                && declaration.kind == VarDeclKind::Var
            {
                collect_declaration_names(declaration, names)?;
            }
            collect_statement_var_declarations(&statement.body, names)?;
        }
        Stmt::ForOf(statement) => {
            if let ForHead::VarDecl(declaration) = &statement.left
                && declaration.kind == VarDeclKind::Var
            {
                collect_declaration_names(declaration, names)?;
            }
            collect_statement_var_declarations(&statement.body, names)?;
        }
        Stmt::Switch(statement) => {
            for case in &statement.cases {
                collect_var_declarations(&case.cons, names)?;
            }
        }
        Stmt::Try(statement) => {
            collect_var_declarations(&statement.block.stmts, names)?;
            if let Some(handler) = &statement.handler {
                collect_var_declarations(&handler.body.stmts, names)?;
            }
            if let Some(finalizer) = &statement.finalizer {
                collect_var_declarations(&finalizer.stmts, names)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_declaration_names(declaration: &VarDecl, names: &mut Vec<String>) -> Result<(), Error> {
    for declarator in &declaration.decls {
        let mut bindings = Vec::new();
        collect_pattern_bindings(&declarator.name, BindingKind::Var, &mut bindings)?;
        names.extend(bindings.into_iter().map(|(name, _)| name));
    }
    Ok(())
}

fn directive_prologue(statements: &[Stmt]) -> (usize, bool) {
    let mut count = 0;
    let mut strict = false;
    for statement in statements {
        let Stmt::Expr(statement) = statement else {
            break;
        };
        let Expr::Lit(Lit::Str(value)) = &*statement.expr else {
            break;
        };
        count += 1;
        strict |= value.value.as_str() == Some("use strict");
    }
    (count, strict)
}

fn is_proto_setter_name(name: &PropName) -> bool {
    match name {
        PropName::Ident(identifier) => identifier.sym == "__proto__",
        PropName::Str(string) => string.value.as_str() == Some("__proto__"),
        _ => false,
    }
}

fn property_function_name(name: &PropName, prefix: &str) -> String {
    let value = match name {
        PropName::Ident(identifier) => identifier.sym.to_string(),
        PropName::Str(string) => match string.value.as_str() {
            Some(value) => value.to_owned(),
            None => return String::new(),
        },
        PropName::Num(number) if number.value == 0.0 => "0".into(),
        PropName::Num(number) => number.value.to_string(),
        PropName::BigInt(value) => value.value.to_string(),
        PropName::Computed(_) => return String::new(),
    };
    format!("{prefix}{value}")
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
            Stmt::Break(_) => "invalid break",
            Stmt::Continue(_) => "invalid continue",
            Stmt::If(_) => "invalid if",
            Stmt::Switch(_) => "switch",
            Stmt::Throw(_) => "throw",
            Stmt::Try(_) => "try",
            Stmt::While(_) => "invalid while",
            Stmt::DoWhile(_) => "invalid do-while",
            Stmt::For(_) => "invalid for",
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
            Expr::Cond(_) => "invalid conditional",
            Expr::New(_) => "new",
            Expr::Update(_) => "update",
            Expr::Yield(_) => "yield",
            Expr::Await(_) => "await",
            Expr::Tpl(_) | Expr::TaggedTpl(_) => "template literal",
            _ => "this",
        }
    ))
}

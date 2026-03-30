#[derive(Debug, Clone, PartialEq)]
/// Stable semantic view of a module used by analysis and editing tools.
pub struct SemanticModule {
    pub version: u32,
    pub functions: Vec<SemanticFunction>,
}

#[derive(Debug, Clone, PartialEq)]
/// Stable semantic view of a function body and its metadata.
pub struct SemanticFunction {
    pub function_index: usize,
    pub name: Option<u32>,
    pub param_count: u32,
    pub frame_size: u32,
    pub environment_size: u32,
    pub instructions: Vec<SemanticInstruction>,
}

#[derive(Debug, Clone, PartialEq)]
/// One lowered semantic instruction.
pub struct SemanticInstruction {
    pub offset: u32,
    pub op: SemanticOp,
}

#[derive(Debug, Clone, PartialEq)]
/// Normalized semantic operations used across Hermes bytecode versions.
pub enum SemanticOp {
    CallBuiltin {
        dst: Register,
        builtin: u32,
        argc: u32,
    },
    CreateEnvironment {
        dst: Register,
    },
    DeclareGlobalVar {
        name: u32,
    },
    DeletePropertyById {
        dst: Register,
        object: Register,
        key: u32,
    },
    DeletePropertyByValue {
        dst: Register,
        object: Register,
        key: Value,
    },
    DirectEval {
        dst: Register,
        callee: Register,
        argument: Value,
    },
    GetEnvironment {
        dst: Register,
        level: u32,
    },
    GetGlobalObject {
        dst: Register,
    },
    GetNewTarget {
        dst: Register,
    },
    LoadParam {
        dst: Register,
        index: u32,
    },
    LoadFromEnvironment {
        dst: Register,
        environment: Register,
        slot: u32,
    },
    LoadImmediate {
        dst: Register,
        value: Immediate,
    },
    Branch {
        kind: BranchKind,
        target: u32,
        args: Vec<Value>,
    },
    CreateClosure {
        kind: ClosureKind,
        dst: Register,
        environment: Register,
        function: u32,
    },
    Construct {
        dst: Register,
        callee: Register,
        argument_count: Value,
    },
    CreateGenerator {
        dst: Register,
        environment: Register,
        function: u32,
    },
    CreateRegExp {
        dst: Register,
        pattern_id: u32,
        flags_id: u32,
        regexp_id: u32,
    },
    CreateThis {
        dst: Register,
        callee: Register,
        new_target: Value,
    },
    LoadConstString {
        dst: Register,
        string: u32,
    },
    LoadThisNS {
        dst: Register,
    },
    Move {
        dst: Register,
        src: Value,
    },
    NewArray {
        dst: Register,
    },
    NewArrayWithBuffer {
        dst: Register,
        min_size: u32,
        max_size: u32,
        buffer_index: u32,
    },
    NewObject {
        dst: Register,
    },
    NewObjectWithBuffer {
        dst: Register,
        key_count: u32,
        value_count: u32,
        key_buffer_index: u32,
        shape_table_index: u32,
    },
    Binary {
        kind: BinaryOpKind,
        dst: Register,
        lhs: Value,
        rhs: Value,
    },
    Unary {
        kind: UnaryOpKind,
        dst: Register,
        operand: Value,
    },
    PropertyGet {
        kind: PropertyAccessKind,
        dst: Register,
        object: Register,
        cache_index: u32,
        key: u32,
    },
    PropertyGetByValue {
        dst: Register,
        object: Register,
        key: Value,
    },
    PropertyPut {
        kind: PropertyAccessKind,
        object: Register,
        value: Value,
        cache_index: u32,
        key: u32,
    },
    PropertyPutByValue {
        object: Register,
        key: Value,
        value: Value,
    },
    PropertyPutOwnByValue {
        object: Register,
        key: Value,
        value: Value,
        enumerable: Value,
    },
    PropertyPutOwnGetterSetterByValue {
        object: Register,
        key: Value,
        getter: Value,
        setter: Value,
        enumerable: Value,
    },
    PropertyDefine {
        kind: PropertyDefineKind,
        object: Register,
        value: Value,
        key: u32,
    },
    PropertyPutIndex {
        object: Register,
        value: Value,
        index: u32,
    },
    Increment {
        dst: Register,
        src: Value,
    },
    Catch {
        dst: Register,
    },
    CompleteGenerator,
    GetArgumentsLength {
        dst: Register,
        arguments: Register,
    },
    GetArgumentsPropByValue {
        dst: Register,
        arguments: Register,
        key: Value,
    },
    GetNextPName {
        dst: Register,
        iterator: Register,
        base: Register,
        index: Register,
        size: Register,
    },
    GetPNameList {
        dst: Register,
        iterator: Register,
        base: Register,
        index: Register,
    },
    IteratorBegin {
        dst: Register,
        source: Register,
    },
    IteratorClose {
        iterator: Register,
        value: Value,
    },
    IteratorNext {
        dst: Register,
        iterator: Register,
        source: Value,
    },
    NewObjectWithParent {
        dst: Register,
        parent: Register,
    },
    ReifyArguments {
        dst: Register,
    },
    ResumeGenerator {
        dst: Register,
        value: Value,
    },
    SaveGenerator {
        value: Value,
    },
    StartGenerator,
    StoreToEnvironment {
        environment: Register,
        value: Value,
        slot: u32,
    },
    SwitchImm {
        input: Value,
        table_offset: u32,
        default_offset: u32,
        min_case: i32,
        max_case: i32,
    },
    Call {
        dst: Register,
        callee: Register,
        this_arg: Option<Register>,
        args: Vec<Value>,
    },
    Return {
        value: Value,
    },
    Throw {
        value: Value,
    },
    Raw {
        mnemonic: String,
        operands: Vec<Value>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Normalized family of control-flow comparisons and jumps.
pub enum BranchKind {
    Jump,
    JumpFalse,
    JumpTrue,
    JumpUndefined,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    NotLess,
    NotLessEqual,
    Equal,
    NotEqual,
    StrictEqual,
    StrictNotEqual,
    NotGreater,
    NotGreaterEqual,
    RawConditional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closure construction mode exposed by Hermes bytecode.
pub enum ClosureKind {
    Normal,
    Generator,
    Async,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Normalized family of binary operators.
pub enum BinaryOpKind {
    Add,
    AddN,
    BitAnd,
    BitOr,
    BitXor,
    Sub,
    SubN,
    Mul,
    MulN,
    Div,
    DivN,
    Eq,
    IsIn,
    LShift,
    Mod,
    Neq,
    RShift,
    StrictEq,
    StrictNeq,
    Greater,
    GreaterEqual,
    InstanceOf,
    Less,
    LessEqual,
    SelectObject,
    URShift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Access mode for property lookup operations.
pub enum PropertyAccessKind {
    ById,
    ByIdShort,
    ByIdLong,
    TryById,
    TryByIdLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Access mode for property-definition style instructions.
pub enum PropertyDefineKind {
    NewOwnById,
    NewOwnByIdShort,
    NewOwnByIdLong,
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// Immediate constant value carried by a semantic instruction.
pub enum Immediate {
    Undefined,
    Null,
    Bool(bool),
    U32(u32),
    I32(i32),
    F64(f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Normalized family of unary operators.
pub enum UnaryOpKind {
    AddEmptyString,
    BitNot,
    Dec,
    Not,
    Negate,
    ToInt32,
    ToNumber,
    ToNumeric,
    TypeOf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Register identifier used by the semantic IR.
pub struct Register(pub u32);

#[derive(Debug, Clone, PartialEq)]
/// Operand value in the semantic IR.
pub enum Value {
    Register(Register),
    U32(u32),
    I32(i32),
    F64(f64),
}

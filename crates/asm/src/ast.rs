#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed semantic assembly module.
pub struct SemanticAssemblyModule {
    pub bytecode_version: Option<u32>,
    pub strings: Vec<String>,
    pub string_kinds: Vec<AssemblyStringKind>,
    pub literal_value_buffer: Vec<u8>,
    pub object_key_buffer: Vec<u8>,
    pub object_shape_table: Vec<SemanticObjectShapeEntry>,
    pub functions: Vec<SemanticAssemblyFunction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Kind of string entry preserved in the semantic assembly text format.
pub enum AssemblyStringKind {
    String,
    Identifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Entry in the preserved object-shape table section.
pub struct SemanticObjectShapeEntry {
    pub key_buffer_offset: u32,
    pub num_props: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed semantic assembly function.
pub struct SemanticAssemblyFunction {
    pub symbol: String,
    pub name: String,
    pub params: u32,
    pub frame: u32,
    pub env: u32,
    pub body: Vec<SemanticAssemblyStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Statement inside a semantic assembly function body.
pub enum SemanticAssemblyStatement {
    Label(String),
    Instruction(SemanticAssemblyInstruction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed semantic assembly instruction.
pub struct SemanticAssemblyInstruction {
    pub offset: Option<u32>,
    pub mnemonic: String,
    pub operands: Vec<SemanticOperand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Operand in the semantic assembly text format.
pub enum SemanticOperand {
    Register(u32),
    Label(String),
    FunctionRef(String),
    String(String),
    Integer(i64),
    Bareword(String),
}

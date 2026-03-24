use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HermesSpec {
    pub hermes_tag: String,
    pub bytecode_version: u32,
    pub bytecode: BytecodeSpec,
    pub container: ContainerSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BytecodeSpec {
    pub operand_types: Vec<OperandTypeSpec>,
    pub instructions: Vec<InstructionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperandTypeSpec {
    pub name: String,
    pub rust_like_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionSpec {
    pub opcode: u16,
    pub name: String,
    pub operands: Vec<InstructionOperandSpec>,
    pub flags: InstructionFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionOperandSpec {
    pub index: u8,
    pub kind: String,
    pub meaning: Option<OperandMeaning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InstructionFlags {
    pub has_ret_target: bool,
    pub is_value_buffer_user: bool,
    pub is_jump_long_variant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperandMeaning {
    BigIntId,
    FunctionId,
    StringId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSpec {
    pub magic: String,
    pub delta_magic: String,
    pub file_header: StructSpec,
    pub function_header: StructSpec,
    pub sections: Vec<SectionSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructSpec {
    pub name: String,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: String,
    pub type_name: String,
    pub since_bytecode_version: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionSpec {
    pub name: String,
    pub alignment: Option<u32>,
    pub notes: Vec<String>,
}

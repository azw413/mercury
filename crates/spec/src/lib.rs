//! Shared serializable schema for extracted Hermes specs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Canonical extracted description of one Hermes bytecode version.
pub struct HermesSpec {
    pub hermes_tag: String,
    pub bytecode_version: u32,
    pub bytecode: BytecodeSpec,
    pub container: ContainerSpec,
    pub semantic: SemanticSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Versioned opcode metadata used by decode, encode, and lowering layers.
pub struct BytecodeSpec {
    pub operand_types: Vec<OperandTypeSpec>,
    pub instructions: Vec<InstructionSpec>,
    pub builtins: Vec<BuiltinSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Known operand kind in a particular Hermes bytecode version.
pub struct OperandTypeSpec {
    pub name: String,
    pub rust_like_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Description of a single opcode in a specific Hermes version.
pub struct InstructionSpec {
    pub opcode: u16,
    pub name: String,
    pub operands: Vec<InstructionOperandSpec>,
    pub flags: InstructionFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Description of one operand in an instruction definition.
pub struct InstructionOperandSpec {
    pub index: u8,
    pub kind: String,
    pub meaning: Option<OperandMeaning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
/// Flags attached to an opcode definition.
pub struct InstructionFlags {
    pub has_ret_target: bool,
    pub is_value_buffer_user: bool,
    pub is_jump_long_variant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Known semantic role for an instruction operand.
pub enum OperandMeaning {
    BigIntId,
    FunctionId,
    StringId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Versioned raw file/container-format description for Hermes bytecode.
pub struct ContainerSpec {
    pub magic: String,
    pub delta_magic: String,
    pub bytecode_options: BitfieldSpec,
    pub file_header: StructSpec,
    pub function_header_flags: BitfieldSpec,
    pub function_header: StructSpec,
    pub raw_module: RawModuleSpec,
    pub sections: Vec<SectionSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Generic struct layout extracted from Hermes headers/macros.
pub struct StructSpec {
    pub name: String,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Field in a [`StructSpec`].
pub struct FieldSpec {
    pub name: String,
    pub type_name: String,
    pub since_bytecode_version: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Bitfield layout extracted from Hermes container definitions.
pub struct BitfieldSpec {
    pub name: String,
    pub fields: Vec<BitfieldFieldSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// One entry in a [`BitfieldSpec`].
pub struct BitfieldFieldSpec {
    pub name: String,
    pub type_name: String,
    pub bit_width: u8,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Raw, versioned description of the module-level serialized sections Mercury models.
pub struct RawModuleSpec {
    pub function_header: RawFunctionHeaderSpec,
    pub function_body: RawFunctionBodySpec,
    pub function_info: RawFunctionInfoSpec,
    pub exception_handlers: RawExceptionHandlerSpec,
    pub debug_offsets: RawDebugOffsetsSpec,
    pub debug_info: RawDebugInfoSpec,
    pub string_table: RawStringTableSpec,
    pub array_buffer: RawBufferSpec,
    pub object_key_buffer: RawBufferSpec,
    pub object_value_buffer: RawBufferSpec,
    pub bigint_table: RawTableSpec,
    pub regexp_table: RawTableSpec,
    pub cjs_module_table: RawTableSpec,
    pub function_source_table: RawTableSpec,
    pub footer: RawFooterSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Versioned layout of small and overflowed function headers.
pub struct RawFunctionHeaderSpec {
    pub small_header_fields: Vec<FieldSpec>,
    pub small_header_flags: String,
    pub large_header_fields: Vec<FieldSpec>,
    pub overflow_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Serializer rules for the raw opcode stream and body-adjacent data.
pub struct RawFunctionBodySpec {
    pub opcode_stream_alignment: Option<u32>,
    pub jump_table_alignment: Option<u32>,
    pub jump_tables_inlined_after_opcodes: bool,
    pub optional_padding_control: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Layout of per-function info records.
pub struct RawFunctionInfoSpec {
    pub info_alignment: Option<u32>,
    pub large_header_may_be_present: bool,
    pub subsections: Vec<RawSubsectionSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Metadata for raw exception-handler tables.
pub struct RawExceptionHandlerSpec {
    pub header_name: String,
    pub table_entry_type: String,
    pub alignment: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Metadata for raw debug-offset records.
pub struct RawDebugOffsetsSpec {
    pub record_type: String,
    pub alignment: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Metadata for serialized debug-info sections.
pub struct RawDebugInfoSpec {
    pub header_name: String,
    pub alignment: Option<u32>,
    pub subsections: Vec<RawSubsectionSpec>,
    pub strip_behavior: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Strategy used to encode Hermes string table entries.
pub struct RawStringTableSpec {
    pub small_entry_type: String,
    pub overflow_entry_type: String,
    pub overflow_strategy: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Opaque raw buffer section such as array or object-key storage.
pub struct RawBufferSpec {
    pub alignment: Option<u32>,
    pub storage: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Typed raw table section such as CJS modules or function-source pairs.
pub struct RawTableSpec {
    pub alignment: Option<u32>,
    pub entry_type: String,
    pub storage: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Footer and checksum metadata for the serialized file.
pub struct RawFooterSpec {
    pub type_name: String,
    pub hash_description: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Named nested subsection within a raw structure.
pub struct RawSubsectionSpec {
    pub name: String,
    pub alignment: Option<u32>,
    pub storage: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Top-level serialized section plus its alignment constraints.
pub struct SectionSpec {
    pub name: String,
    pub alignment: Option<u32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Builtin object or method declared by Hermes for a given version.
pub struct BuiltinSpec {
    pub index: u32,
    pub kind: BuiltinKind,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Category of builtin entry declared in `Builtins.def`.
pub enum BuiltinKind {
    BuiltinObject,
    BuiltinMethod,
    PrivateBuiltin,
    JsBuiltin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Version-independent semantic schema Mercury aims to expose to users.
pub struct SemanticSpec {
    pub module: SemanticModuleSpec,
    pub function: SemanticFunctionSpec,
    pub instruction: SemanticInstructionSpec,
    pub exception_handler: SemanticExceptionHandlerSpec,
    pub debug_info: SemanticDebugInfoSpec,
    pub side_tables: Vec<SemanticSideTableSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic module shape exposed by the extracted spec.
pub struct SemanticModuleSpec {
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic function shape exposed by the extracted spec.
pub struct SemanticFunctionSpec {
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic instruction shape exposed by the extracted spec.
pub struct SemanticInstructionSpec {
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic exception-handler shape exposed by the extracted spec.
pub struct SemanticExceptionHandlerSpec {
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic debug-info shape exposed by the extracted spec.
pub struct SemanticDebugInfoSpec {
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Semantic side-table shape exposed by the extracted spec.
pub struct SemanticSideTableSpec {
    pub name: String,
    pub fields: Vec<SemanticFieldSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Named field in one of the semantic schema descriptions.
pub struct SemanticFieldSpec {
    pub name: String,
    pub type_name: String,
    pub source: String,
    pub notes: Vec<String>,
}

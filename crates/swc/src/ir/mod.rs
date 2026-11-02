//! Raw and normalized intermediate representations for Hermes bytecode, plus
//! lowering from raw decoded instructions into the stable semantic model.

pub mod lower;
pub mod raw;
pub mod semantic;

pub use lower::{LoweringError, lower_function, lower_instruction, lower_module};
pub use raw::{
    RawExceptionHandler, RawFunction, RawFunctionFlags, RawInstruction, RawModule, RawOperand,
    RawSectionBoundaries, RawStringSwitchCase, RawStringSwitchTable, RawSwitchTable,
};
pub use semantic::{
    BinaryOpKind, BranchKind, ClosureKind, Immediate, PropertyAccessKind, PropertyDefineKind,
    Register, SemanticFunction, SemanticInstruction, SemanticModule, SemanticOp, UnaryOpKind,
    Value,
};

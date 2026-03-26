pub mod raw;
pub mod semantic;
pub mod lower;

pub use lower::{lower_function, lower_instruction, lower_module, LoweringError};
pub use raw::{
    RawFunction, RawFunctionFlags, RawInstruction, RawModule, RawOperand, RawSectionBoundaries,
};
pub use semantic::{
    BinaryOpKind, BranchKind, ClosureKind, Immediate, PropertyAccessKind, PropertyDefineKind,
    Register, SemanticFunction, SemanticInstruction, SemanticModule, SemanticOp, UnaryOpKind,
    Value,
};

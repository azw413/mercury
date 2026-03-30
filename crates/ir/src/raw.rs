#[derive(Debug, Clone, PartialEq)]
/// Lossless raw view of a Hermes bytecode module after binary decoding.
pub struct RawModule {
    pub version: u32,
    pub function_count: u32,
    pub sections: RawSectionBoundaries,
    pub functions: Vec<RawFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Raw section boundary information preserved from the source container.
pub struct RawSectionBoundaries {
    pub function_bodies_start: usize,
}

#[derive(Debug, Clone, PartialEq)]
/// Lossless raw view of a single decoded Hermes function.
pub struct RawFunction {
    pub function_index: usize,
    pub offset: u32,
    pub bytecode_size_in_bytes: u32,
    pub param_count: u32,
    pub frame_size: u32,
    pub environment_size: u32,
    pub highest_read_cache_index: u8,
    pub highest_write_cache_index: u8,
    pub flags: RawFunctionFlags,
    pub instructions: Vec<RawInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Function flags copied directly from the Hermes function header.
pub struct RawFunctionFlags {
    pub prohibit_invoke: u8,
    pub strict_mode: bool,
    pub has_exception_handler: bool,
    pub has_debug_info: bool,
    pub overflowed: bool,
}

#[derive(Debug, Clone, PartialEq)]
/// Decoded raw instruction with its original opcode and typed operands.
pub struct RawInstruction {
    pub offset: u32,
    pub opcode: u16,
    pub name: String,
    pub size: usize,
    pub operands: Vec<RawOperand>,
}

#[derive(Debug, Clone, PartialEq)]
/// Typed raw operand value used by [`RawInstruction`].
pub enum RawOperand {
    U8(u8),
    U16(u16),
    U32(u32),
    I8(i8),
    I32(i32),
    F64(f64),
}

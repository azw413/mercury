//! Binary parser, decoder, encoder, and minimal module builder for Hermes
//! bytecode containers.

mod decode;
mod encode;
mod functions;
mod header;
mod module;
mod parse;
mod sections;
mod tables;

pub use decode::{
    DecodedInstruction, DecodedOperand, HbcDecodeError, decode_function_instructions,
    decode_raw_function, decode_raw_module,
};
pub use encode::{HbcEncodeError, encode_instruction, encode_instructions};
pub use functions::{
    DebugOffsetsEntry, ExceptionHandlerEntry, FunctionBody, FunctionHeader, FunctionHeaderFlags,
    FunctionInfo, write_debug_offsets, write_exception_handler_table, write_large_function_header,
    write_large_function_header_for_version, write_small_function_header,
    write_small_function_header_for_version,
};
pub use header::{BytecodeOptions, HbcHeaderLayout, HbcVersionedFileHeader, write_file_header};
pub use module::{HbcBuildError, HbcString, MinimalFunction, MinimalModule, build_minimal_module};
pub use parse::{HbcContainer, HbcParseError, parse_hbc_container, parse_hbc_container_with_spec};
pub use sections::HbcSectionBoundaries;
pub use tables::{
    OverflowStringTableEntry, PairTableEntry, ShapeTableEntry, SmallStringTableEntry, StringKind,
    StringKindEntry, write_overflow_string_table_entries, write_pair_table_entries,
    write_shape_table_entries, write_small_string_table_entries, write_string_kind_entries,
};

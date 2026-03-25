mod decode;
mod encode;
mod functions;
mod header;
mod parse;
mod sections;
mod tables;

pub use decode::{
    decode_function_instructions, decode_raw_function, decode_raw_module, DecodedInstruction,
    DecodedOperand, HbcDecodeError,
};
pub use encode::{encode_instruction, encode_instructions, HbcEncodeError};
pub use functions::{
    write_debug_offsets, write_exception_handler_table, write_large_function_header,
    write_small_function_header, DebugOffsetsEntry, ExceptionHandlerEntry, FunctionBody,
    FunctionHeader, FunctionHeaderFlags, FunctionInfo,
};
pub use header::{write_file_header, BytecodeOptions, HbcVersionedFileHeader};
pub use sections::HbcSectionBoundaries;
pub use tables::{
    write_overflow_string_table_entries, write_pair_table_entries,
    write_small_string_table_entries, write_string_kind_entries, OverflowStringTableEntry,
    PairTableEntry, SmallStringTableEntry, StringKind, StringKindEntry,
};
pub use parse::{
    parse_hbc_container, parse_hbc_container_with_spec, HbcContainer, HbcParseError,
};

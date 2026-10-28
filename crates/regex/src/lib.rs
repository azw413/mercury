//! Hermes regular-expression compiler: turns a RegExp pattern and flags into
//! the regex bytecode that HBC stores for `CreateRegExp`.
//!
//! The Hermes VM never compiles a literal's pattern itself; it runs the
//! bytecode in the module's regexp storage. This crate is a port of the
//! compiler half of Hermes's `lib/Regex` (rn/0.73-stable through
//! rn/0.76-stable, which all ship HBC 96 and share one regex bytecode format)
//! and produces the same bytes as `hermesc`, including its quirks. Hermes is
//! MIT licensed and its regex engine derives from libc++; see `LICENSE-hermes`
//! and `LICENSE-libcxx`.

mod flags;
mod node;
mod parser;
mod unicode;
mod unicode_data;

pub use flags::SyntaxFlags;

/// Why a pattern or flags string was rejected. The messages are Hermes's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegexError {
    #[error("Escaped value too large")]
    EscapeOverflow,
    #[error("Incomplete escape")]
    EscapeIncomplete,
    #[error("Invalid escape")]
    EscapeInvalid,
    #[error("Character class not closed")]
    UnbalancedBracket,
    #[error("Parenthesized expression not closed")]
    UnbalancedParenthesis,
    #[error("Quantifier range out of order")]
    BraceRange,
    #[error("Character class range out of order")]
    CharacterRange,
    #[error("Invalid quantifier bracket")]
    InvalidQuantifierBracket,
    #[error("Quantifier has nothing to repeat")]
    InvalidRepeat,
    #[error("Pattern exceeds parse limits")]
    PatternExceedsParseLimits,
    #[error("Invalid flags")]
    InvalidFlags,
    #[error("Invalid capture group name")]
    InvalidCaptureGroupName,
    #[error("Duplicate capture group name")]
    DuplicateCaptureGroupName,
    #[error("Invalid named reference")]
    InvalidNamedReference,
    #[error("Nonexistent named capture reference")]
    NonexistentNamedCaptureReference,
    #[error("Invalid property name")]
    InvalidPropertyName,
}

/// A compiled regular expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRegex {
    /// Hermes regex bytecode: a 6-byte header followed by instructions.
    pub bytecode: Vec<u8>,
    /// Named groups in definition order, as UTF-16 names and 1-based group
    /// numbers. The bytecode doesn't record them: hermesc follows
    /// `CreateRegExp` with a call to the `initRegexNamedGroups` builtin,
    /// passing an object that maps each name to its number.
    pub group_names: Vec<(Vec<u16>, u32)>,
}

/// Compile `pattern` with `flags`, both as UTF-16 code units (a literal's
/// source text between the slashes, and after the last one).
pub fn compile(pattern: &[u16], flags: &[u16]) -> Result<CompiledRegex, RegexError> {
    let flags = SyntaxFlags::parse(flags).ok_or(RegexError::InvalidFlags)?;
    let regex = parser::Regex::parse(pattern, flags)?;
    Ok(CompiledRegex {
        bytecode: regex.compile(),
        group_names: regex.group_names(),
    })
}

/// [`compile`] for a pattern and flags held as Rust strings.
pub fn compile_str(pattern: &str, flags: &str) -> Result<CompiledRegex, RegexError> {
    let pattern: Vec<u16> = pattern.encode_utf16().collect();
    let flags: Vec<u16> = flags.encode_utf16().collect();
    compile(&pattern, &flags)
}

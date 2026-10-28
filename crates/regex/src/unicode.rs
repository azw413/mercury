//! Character properties and case canonicalisation, ported from Hermes's
//! `CharacterProperties.cpp` and `CodePointSet.h` over its own tables.

use crate::unicode_data::*;

pub const UNICODE_MAX_VALUE: u32 = 0x10FFFF;
const UNICODE_ZWNJ: u32 = 0x200C;
const UNICODE_ZWJ: u32 = 0x200D;

pub fn is_high_surrogate(cp: u32) -> bool {
    (0xD800..0xDC00).contains(&cp)
}

pub fn is_low_surrogate(cp: u32) -> bool {
    (0xDC00..=0xDFFF).contains(&cp)
}

pub fn surrogate_pair_to_code_point(lead: u32, trail: u32) -> u32 {
    ((lead - 0xD800) << 10) + (trail - 0xDC00) + 0x10000
}

fn in_table(table: &[(u32, u32)], cp: u32) -> bool {
    let index = table.partition_point(|&(_, last)| last < cp);
    index < table.len() && table[index].0 <= cp
}

pub fn is_unicode_id_start(cp: u32) -> bool {
    cp == u32::from(b'_')
        || cp == u32::from(b'$')
        || (u32::from(b'a')..=u32::from(b'z')).contains(&(cp | 32))
        || (cp > 0x7F && in_table(UNICODE_LETTERS, cp))
}

pub fn is_unicode_id_continue(cp: u32) -> bool {
    is_unicode_id_start(cp)
        || in_table(UNICODE_COMBINING_MARK, cp)
        || is_unicode_digit(cp)
        || cp == u32::from(b'_')
        || in_table(UNICODE_CONNECTOR_PUNCTUATION, cp)
        || cp == UNICODE_ZWNJ
        || cp == UNICODE_ZWJ
}

fn is_unicode_digit(cp: u32) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&cp) || in_table(UNICODE_DIGIT, cp)
}

pub fn is_unicode_property_name(cp: u32) -> bool {
    cp == u32::from(b'_') || (u32::from(b'a')..=u32::from(b'z')).contains(&(cp | 32))
}

pub fn is_unicode_property_value(cp: u32) -> bool {
    is_unicode_property_name(cp) || is_unicode_digit(cp)
}

/// A half-open run `[first, first + length)` of code points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePointRange {
    pub first: u32,
    pub length: u32,
}

impl CodePointRange {
    pub fn end(self) -> u32 {
        self.first + self.length
    }

    fn overlaps(self, other: Self) -> bool {
        self.first < other.end() && other.first < self.end()
    }
}

/// Sorted ranges, merged whenever they overlap or touch, so equal sets have
/// equal range lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodePointSet {
    ranges: Vec<CodePointRange>,
}

impl CodePointSet {
    pub fn add_range(&mut self, range: CodePointRange) {
        if range.length == 0 {
            return;
        }
        // The ranges that overlap or abut `range` are contiguous.
        let start = self.ranges.partition_point(|r| r.end() < range.first);
        let end = self.ranges.partition_point(|r| r.first <= range.end());
        if start == end {
            self.ranges.insert(start, range);
            return;
        }
        let first = range.first.min(self.ranges[start].first);
        let last = range.end().max(self.ranges[end - 1].end());
        self.ranges[start] = CodePointRange {
            first,
            length: last - first,
        };
        self.ranges.drain(start + 1..end);
    }

    pub fn add(&mut self, cp: u32) {
        self.add_range(CodePointRange {
            first: cp,
            length: 1,
        });
    }

    pub fn ranges(&self) -> &[CodePointRange] {
        &self.ranges
    }
}

/// One `(start, count, delta, modulo)` entry: code points `start..start+count`
/// whose offset from `start` is a multiple of `modulo` map to `cp + delta`.
type Transform = (u32, u8, i32, u8);

fn transforms(unicode: bool) -> &'static [Transform] {
    if unicode {
        UNICODE_FOLDS
    } else {
        LEGACY_CANONS
    }
}

fn transform_end(transform: &Transform) -> u32 {
    transform.0 + u32::from(transform.1)
}

fn apply_transform(transform: &Transform, cp: u32) -> u32 {
    if (cp - transform.0).is_multiple_of(u32::from(transform.3)) {
        cp.wrapping_add_signed(transform.2)
    } else {
        cp
    }
}

/// The first transform ending after `cp`.
fn transform_at(table: &[Transform], cp: u32) -> usize {
    table.partition_point(|t| transform_end(t) <= cp)
}

/// ES Canonicalize(ch): simple case folding with `u`, upper-casing without.
pub fn canonicalize(cp: u32, unicode: bool) -> u32 {
    if cp <= 127 {
        if (cp as u8).is_ascii_alphabetic() {
            return (cp & !(1 << 5)) | (u32::from(unicode) << 5);
        }
        return cp;
    }
    let table = transforms(unicode);
    match table.get(transform_at(table, cp)) {
        Some(transform) if transform.0 <= cp => apply_transform(transform, cp),
        _ => cp,
    }
}

fn canonicalize_range(range: CodePointRange, receiver: &mut CodePointSet, unicode: bool) {
    let table = transforms(unicode);
    let mut index = transform_at(table, range.first);
    let mut cp = range.first;
    let end = range.end();
    while cp < end && index < table.len() {
        let transform = &table[index];
        if transform.0 > cp {
            cp = transform.0;
        } else {
            while cp < transform_end(transform) && cp < end {
                receiver.add(apply_transform(transform, cp));
                cp += 1;
            }
            index += 1;
        }
    }
}

fn add_precanonical_characters(range: CodePointRange, receiver: &mut CodePointSet, unicode: bool) {
    if range.length == 0 {
        return;
    }
    for transform in transforms(unicode) {
        let to = CodePointRange {
            first: transform.0.wrapping_add_signed(transform.2),
            length: u32::from(transform.1),
        };
        if !range.overlaps(to) {
            continue;
        }
        for cp in transform.0..transform_end(transform) {
            let target = apply_transform(transform, cp);
            if target != cp && range.first <= target && target < range.end() {
                receiver.add(cp);
            }
        }
    }
}

/// Every code point that canonicalizes to the same value as some member of
/// `set`.
pub fn make_canonically_equivalent(set: &CodePointSet, unicode: bool) -> CodePointSet {
    let mut canonicalized = set.clone();
    for &range in set.ranges() {
        canonicalize_range(range, &mut canonicalized, unicode);
    }
    let mut result = canonicalized.clone();
    for &range in canonicalized.ranges() {
        add_precanonical_characters(range, &mut result, unicode);
    }
    result
}

fn pool_str(offset: u16, size: u16) -> &'static str {
    &STRING_POOL[usize::from(offset)..usize::from(offset) + usize::from(size)]
}

fn find_name(
    table: &'static [(u16, u16, u16, u16)],
    name: &str,
) -> Option<&'static (u16, u16, u16, u16)> {
    let index = table.partition_point(|entry| pool_str(entry.0, entry.1) < name);
    table
        .get(index)
        .filter(|entry| pool_str(entry.0, entry.1) == name)
}

/// The `RANGE_ARRAY_POOL` slice for `\p{name}` or `\p{name=value}`, or `None`
/// if Hermes doesn't know the property.
pub fn property_ranges(name: &str, value: &str) -> Option<&'static [(u16, u16)]> {
    let (names, ranges) = if value.is_empty() {
        // A lone name is a binary property or a General_Category value.
        if find_name(NAMES_BINARY_PROPERTY, name).is_some() {
            (NAMES_BINARY_PROPERTY, RANGES_BINARY_PROPERTY)
        } else {
            (NAMES_GENERAL_CATEGORY, RANGES_GENERAL_CATEGORY)
        }
    } else {
        match name {
            "General_Category" | "gc" => (NAMES_GENERAL_CATEGORY, RANGES_GENERAL_CATEGORY),
            "Script" | "sc" => (NAMES_SCRIPT, RANGES_SCRIPT),
            // Script_Extensions shares Script's value names.
            "Script_Extensions" | "scx" => (NAMES_SCRIPT, RANGES_SCRIPT_EXTENSIONS),
            _ => return None,
        }
    };
    let canonical = find_name(names, if value.is_empty() { name } else { value })?;
    let entry = find_name(ranges, pool_str(canonical.2, canonical.3))?;
    let start = usize::from(entry.2);
    Some(&RANGE_ARRAY_POOL[start..start + usize::from(entry.3)])
}

/// Add a property's ranges to `receiver`. Inverting complements each pool
/// separately and stops short of U+10FFFF, as Hermes does.
pub fn add_property_ranges(receiver: &mut CodePointSet, pools: &[(u16, u16)], inverted: bool) {
    for &(offset, size) in pools {
        let start = usize::from(offset);
        let pool = &RANGE_POOL[start..start + usize::from(size)];
        if inverted {
            let mut last = 0;
            for &(first, end) in pool {
                receiver.add_range(CodePointRange {
                    first: last,
                    length: first - last,
                });
                last = end + 1;
            }
            receiver.add_range(CodePointRange {
                first: last,
                length: UNICODE_MAX_VALUE - last,
            });
        } else {
            for &(first, end) in pool {
                receiver.add_range(CodePointRange {
                    first,
                    length: end - first + 1,
                });
            }
        }
    }
}

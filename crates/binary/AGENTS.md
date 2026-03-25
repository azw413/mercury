# `mercury-binary` Working Notes

This crate should stay organized around binary-format domains, not around broad phases like "all parsing" or "all writing".

## Module layout

Keep Rust modules logically aligned by structure:

- `header.rs`: file header parsing and writing
- `sections.rs`: section sizing, offsets, alignment, and layout helpers
- `functions.rs`: function headers, bodies, function-info blocks, exception tables, debug offsets
- `tables.rs`: string tables, CJS table, function source table, bigint/regexp tables
- `decode.rs`: instruction decoding
- `encode.rs`: instruction encoding

Avoid growing `parse.rs` or `writer.rs` into grab-bag files. If a structure has a parser and a writer, they should live in the same domain module whenever practical.

## Symmetry rule

Implement parsers and writers together for each high-level binary structure.

For each new structure, aim to add all of:

1. typed Rust representation
2. parser
3. writer
4. round-trip unit tests

Do not defer all writing work until "later". Round-tripping is a core requirement of this crate.

## Testing rule

Every high-level structure should have unit tests that exercise parser/writer symmetry.

Preferred pattern:

- parse known bytes into a typed structure
- write the typed structure back to bytes
- assert byte-for-byte equality
- when useful, parse the written bytes again and assert structural equality

For container-level coverage, keep using real `.hbc` fixtures. For structure-level coverage, prefer small focused byte fixtures built directly in tests.

## Design rule

Keep binary-layer types lossless and version-aware.

- Preserve encoding-relevant distinctions.
- Do not normalize away information needed for byte-perfect reassembly.
- Leave semantic normalization to higher crates (`mercury-ir` and above).

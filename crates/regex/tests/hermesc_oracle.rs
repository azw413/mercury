//! Differential test against hermesc: `fixtures/hermesc.jsonl` records what an
//! HBC 96 hermesc does with each pattern (its regexp bytecode, or the error it
//! reports), and our compiler must agree byte for byte.
//!
//! Regenerate with
//! `HERMESC_BIN=/path/to/hermesc cargo test -p mercury-regex -- --ignored regenerate`.

use std::{fs, path::PathBuf, process::Command};

use mercury_binary::parse_hbc_container_with_spec;
use mercury_spec_builtin::load_spec;
use serde_json::{Value, json};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hermesc.jsonl")
}

/// Bytecode as hex, or for long bytecode (big Unicode brackets) its length
/// and FNV-1a hash, to keep the fixture small.
fn summary(bytes: &[u8]) -> String {
    if bytes.len() <= 128 {
        return bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    }
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{} bytes, fnv1a64 {hash:016x}", bytes.len())
}

#[test]
fn bytecode_matches_hermesc() {
    let text = fs::read_to_string(fixture_path()).unwrap();
    let mut checked = 0;
    let mut errors = 0;
    let mut wrong = Vec::new();
    for line in text.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let pattern = case["pattern"].as_str().unwrap();
        let flags = case["flags"].as_str().unwrap();
        let ours = match mercury_regex::compile_str(pattern, flags) {
            Ok(regex) => json!({ "bytecode": summary(&regex.bytecode) }),
            Err(error) => json!({ "error": error.to_string() }),
        };
        let theirs = match case.get("bytecode") {
            Some(bytecode) => json!({ "bytecode": bytecode }),
            None => {
                errors += 1;
                json!({ "error": case["error"] })
            }
        };
        if ours != theirs {
            wrong.push(format!("/{pattern}/{flags}: hermesc {theirs}, ours {ours}"));
        }
        checked += 1;
    }
    assert!(checked > 1500 && errors > 200, "fixture looks truncated");
    assert!(
        wrong.is_empty(),
        "{} of {checked} differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Hand-picked cases: every construct, the Annex B corners, and real-world
/// patterns.
const CASES: &[(&str, &str)] = &[
    // Characters and MatchNChar grouping.
    ("a", ""),
    ("ab", ""),
    ("abc", ""),
    ("abcd", ""),
    ("a\u{e9}b", ""),
    ("\u{e9}", ""),
    ("\u{1F600}", ""),
    ("\u{1F600}", "u"),
    (r"😀", ""),
    (r"😀", "u"),
    (r"\u{1F600}", "u"),
    (r"\uD83D", "u"),
    (r"\uDE00", "u"),
    (r"\uD83Dx", "u"),
    (r"\u{10FFFF}", "u"),
    (r"\u{110000}", "u"),
    (r"\u{}", "u"),
    (r"\u{41", "u"),
    ("x\u{e9}\u{e8}abcd\u{1F600}ef", ""),
    ("x\u{e9}\u{e8}abcd\u{1F600}ef", "u"),
    // Case-insensitive characters and brackets.
    ("abc", "i"),
    ("ABC", "iu"),
    ("a\u{e9}", "i"),
    ("\u{17F}", "i"),
    ("\u{17F}", "iu"),
    ("\u{212A}", "i"),
    ("\u{212A}", "iu"),
    ("k", "iu"),
    ("s", "iu"),
    ("\u{DF}", "iu"),
    ("[a-z]", "i"),
    ("[A-Z]", "iu"),
    ("[\u{e0}-\u{ff}]", "i"),
    ("[^a]", "i"),
    (r"[Ā-ſ]", "i"),
    (r"[Ā-ſ]", "iu"),
    ("[k]", "iu"),
    ("[\u{3A3}]", "i"),
    ("[\u{3C3}\u{3C2}]", "iu"),
    (r"[\u{10400}-\u{1044F}]", "iu"),
    ("\u{10400}", "iu"),
    ("[a-zA-Z0-9]", "i"),
    (r"[^\x00-\x7f]", "i"),
    ("[\u{1F600}]", "iu"),
    // Character classes.
    (r"\d", ""),
    (r"\D", ""),
    (r"\s", ""),
    (r"\S", ""),
    (r"\w", ""),
    (r"\W", ""),
    (r"\w", "iu"),
    (r"[\d]", ""),
    (r"[\D\s]", ""),
    (r"[^\w\W]", ""),
    (r"[\d-z]", ""),
    (r"[a-\d]", ""),
    (r"[\d-z]", "u"),
    ("[a-]", ""),
    ("[-a]", ""),
    (r"[\b]", ""),
    ("[^]", ""),
    ("[]", ""),
    (r"[\]]", ""),
    ("[a-z0-9_]", ""),
    (r"[^\x00-\x7f]", ""),
    ("[^\0-\x7f]", ""),
    (r"[\u{1F600}-\u{1F64F}]", "u"),
    ("[\u{1F600}-\u{1F64F}]", "u"),
    ("[\u{1F600}]", ""),
    ("[z-a]", ""),
    (r"[\-]", "u"),
    (r"[\-]", ""),
    (r"\-", "u"),
    ("[a-a]", ""),
    ("[aaa]", ""),
    ("[a-cb-d]", ""),
    ("[a-cd-f]", ""),
    ("[\u{80}-\u{FFFF}]", ""),
    ("[\u{80}-\u{FFFF}]", "u"),
    (r"[\s\S]", ""),
    (r"[\uD800-\uDBFF][\uDC00-\uDFFF]", ""),
    (r"[\uD800-\uDFFF]", "u"),
    // Anchors and assertions.
    ("^a$", ""),
    ("^a", "m"),
    ("(?:^)", ""),
    (r"\bfoo\B", ""),
    (r"\b*", ""),
    ("^*", ""),
    ("$+", ""),
    ("a^b", ""),
    ("^|$", ""),
    ("^", "my"),
    // Dot.
    (".", ""),
    (".", "s"),
    (".", "u"),
    (".", "su"),
    (".*", ""),
    (".*", "u"),
    (".+?", "s"),
    // Quantifiers.
    ("a*", ""),
    ("a+", ""),
    ("a?", ""),
    ("a{2}", ""),
    ("a{2,}", ""),
    ("a{2,5}", ""),
    ("a*?", ""),
    ("a+?", ""),
    ("a{2,5}?", ""),
    ("(ab)*", ""),
    ("(?:ab)*", ""),
    ("(a)*", ""),
    ("(?:a|b)*", ""),
    ("(a|b)+?", ""),
    ("x{0}", ""),
    ("x{0,0}", ""),
    ("{", ""),
    ("a{", ""),
    ("a{2", ""),
    ("a{,5}", ""),
    ("a{5,3}", ""),
    ("*a", ""),
    ("a**", ""),
    ("a{2}{3}", ""),
    ("{", "u"),
    ("}", ""),
    ("}", "u"),
    ("]", ""),
    ("]", "u"),
    ("a{99999999999}", ""),
    ("a{4294967295,}", ""),
    ("a{2,1}?", ""),
    ("\u{e9}*", ""),
    ("\u{1F600}*", ""),
    ("\u{1F600}*", "u"),
    ("[a-z]*", ""),
    ("[a-z]*", "u"),
    (r"\d+", ""),
    ("(?:a*)*", ""),
    ("(?:a?)+", ""),
    ("(a*)*", ""),
    ("(?:ab|cd)+", ""),
    ("(?:a|)*", ""),
    ("a{3}b{0,1}", "i"),
    (r"(?:\s|x)*y", ""),
    ("a*b*c*", ""),
    (r"\b+", "u"),
    // Groups and alternation.
    ("(a)(b)(c)", ""),
    ("(?:a)", ""),
    ("((a)|b)", ""),
    ("(a|b|c|d)", ""),
    ("a|b|c", ""),
    ("|", ""),
    ("a|", ""),
    ("(|a)", ""),
    ("((((((((((a))))))))))", ""),
    ("(?:(?:(?:a)))", ""),
    ("(", ""),
    (")", ""),
    ("a)", ""),
    ("((a)", ""),
    ("(?", ""),
    ("(?a)", ""),
    ("(?:", ""),
    ("a(bc)d", ""),
    ("ab(cd)ef", ""),
    ("(ab)cd", ""),
    ("a|bc|def", ""),
    ("(a)|(b)", ""),
    ("x(?:ab|ac)y", "i"),
    ("(?:)", ""),
    ("()", ""),
    ("(?=)", ""),
    // Hermes never optimizes inside the node that ends a run of characters.
    ("a(bcde)f", ""),
    ("a(?:bcde)*", ""),
    ("ab(?=cdef)", ""),
    ("xa(bcd|efgh)", ""),
    ("a[b](cdef)", ""),
    ("(abcd)(efgh)", ""),
    ("a(b(cdef))", ""),
    ("ab(?<=cdef)g", ""),
    ("abc(?:d|efgh|ijkl)", "i"),
    ("\u{e9}(abcd)", ""),
    ("(?:abcd)+efgh", ""),
    // Named groups and references.
    (r"(?<name>a)\k<name>", ""),
    (r"\k<name>(?<name>a)", ""),
    ("(?<a>.)(?<a>.)", ""),
    (r"\k<nope>(?<a>x)", ""),
    (r"(?<a>x)\k<nope>", ""),
    (r"\k", ""),
    (r"\k<a>", ""),
    (r"\k<a>", "u"),
    (r"\k", "u"),
    ("(?<\u{1D49C}>x)", "u"),
    ("(?<\u{1D49C}>x)", ""),
    (r"(?<ab>x)", ""),
    (r"(?<a\u{62}>x)", ""),
    (r"(?<a\u{62}>x)\k<ab>", "u"),
    ("(?<>a)", ""),
    ("(?<1a>x)", ""),
    ("(?<a", ""),
    ("(?<$_>x)", ""),
    ("(?<a\u{e9}>x)", ""),
    (r"(?<a>x)|(?<b>y)\k<a>", ""),
    (r"\k<a>x(?<a>y)", "i"),
    (r"(?<a>a)\1\k<a>", ""),
    (r"(?<\u{10000}>x)", "u"),
    (r"\k<a", ""),
    (r"(?<a>x)\k<a", ""),
    // Numbered references and octal escapes.
    (r"(a)\1", ""),
    (r"\1(a)", ""),
    (r"(a)\2", ""),
    (r"\8", ""),
    (r"\10", ""),
    (r"\9", "u"),
    (r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\10", ""),
    (r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\11", ""),
    (r"\0", ""),
    (r"\01", ""),
    (r"\377", ""),
    (r"\400", ""),
    (r"\0", "u"),
    (r"\01", "u"),
    (r"(a)\1", "i"),
    (r"(a)\2", "u"),
    (r"\1", "u"),
    (r"(a)\1", "u"),
    (r"[\1]", ""),
    (r"[\8]", ""),
    (r"[\0]", ""),
    (r"\777", ""),
    (r"\18", ""),
    // Lookarounds.
    ("(?=a)", ""),
    ("(?!a)", ""),
    ("(?<=a)b", ""),
    ("(?<!ab)c", ""),
    ("(?<=(a)(b))c", ""),
    ("(?<=a(?=b))", ""),
    ("(?=a)*", ""),
    ("(?=a)*", "u"),
    ("(?<=a)*", ""),
    ("(?!a)+", ""),
    ("(?<=^abc)def", ""),
    ("(?<=a|bc)d", ""),
    ("(?<=x+)y", ""),
    ("(?<=abc)", "i"),
    ("(?<=[a-z]{2})\\d", ""),
    ("(?<=(?<=a)b)c", ""),
    ("(?<=a(?<=b)c)", ""),
    ("(?=^)", ""),
    ("(?!^a)b", ""),
    ("(?<=\u{1F600})x", "u"),
    ("(?<=a\u{e9}b)", ""),
    (r"(?<=(\d+)(\d+))$", ""),
    // Escapes.
    (r"\x41", ""),
    (r"\x4", ""),
    (r"\xZZ", ""),
    (r"A", ""),
    (r"\u004", ""),
    (r"\u{41}", ""),
    (r"\u{2}", ""),
    (r"\cA", ""),
    (r"\cz", ""),
    (r"\c1", ""),
    (r"\c", ""),
    (r"[\c1]", ""),
    (r"[\c_]", ""),
    (r"\f\n\r\t\v", ""),
    (r"\/", ""),
    (r"\q", ""),
    (r"\q", "u"),
    (r"\x4", "u"),
    (r"\c1", "u"),
    (r"\u004", "u"),
    (r"\.\*\+\?\(\)\[\]\{\}\|\^\$\\", "u"),
    (r"\\", ""),
    (r"\e\g\h\i\j\l\m\o", ""),
    (r"\a", "u"),
    (r"\_", ""),
    ("\\\u{e9}", ""),
    ("\\\u{e9}", "u"),
    // Unicode property escapes.
    (r"\p{L}", "u"),
    (r"\P{L}", "u"),
    (r"\p{Lu}", "u"),
    (r"\p{Script=Greek}", "u"),
    (r"\p{sc=Grek}", "u"),
    (r"\p{scx=Latn}", "u"),
    (r"\p{General_Category=Letter}", "u"),
    (r"\p{gc=Nd}", "u"),
    (r"\p{ASCII}", "u"),
    (r"\p{Any}", "u"),
    (r"\p{Assigned}", "u"),
    (r"\p{ASCII_Hex_Digit}", "u"),
    (r"\p{Emoji}", "u"),
    (r"[\p{L}\d]", "u"),
    (r"[\P{L}]", "u"),
    (r"[^\p{N}]", "u"),
    (r"[\P{Lu}a]", "u"),
    (r"\p{Foo}", "u"),
    (r"\p{L}", ""),
    (r"\P{L}", ""),
    (r"\p{gc=Lu}", "iu"),
    (r"\p{Lowercase}", "iu"),
    (r"\p", "u"),
    (r"\p{}", "u"),
    (r"\p{Script=}", "u"),
    (r"\p{L", "u"),
    (r"\p{Foo=Bar}", "u"),
    (r"\p{Script=Foo}", "u"),
    (r"\p{L}+", "u"),
    (r"\P{L}*", "u"),
    (r"[\p{L}-z]", "u"),
    (r"\p{Script_Extensions=Hira}", "u"),
    (r"\p{sc=Han}\p{scx=Han}", "u"),
    (r"\p{Lu}", "iu"),
    (r"[^\P{L}]", "u"),
    (r"\p{l}", "u"),
    (r"\p{RGI_Emoji}", "u"),
    (r"\p{Cased_Letter}", "u"),
    (r"\p{LC}", "u"),
    (r"\p{C}", "u"),
    // Flags.
    ("a", "gimsuyd"),
    ("a", "gg"),
    ("a", "x"),
    ("a", "v"),
    ("a", "dgimsy"),
    ("a", "uu"),
    // Real-world patterns.
    (r"^[\w.+-]+@[\w-]+\.[\w.-]+$", ""),
    (r"^https?:\/\/[^\s/$.?#].[^\s]*$", "i"),
    (
        r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)(Z|[+-]\d{2}:\d{2})?$",
        "",
    ),
    (
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$",
        "",
    ),
    (
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$",
        "",
    ),
    (r"^\s+|\s+$", "g"),
    (r"([a-z])([A-Z])", "g"),
    (r"^[\w$]+$", ""),
    (r"[  ]", "g"),
    (r"^(?:[a-z]+:)?\/\/", "i"),
    (r"%[sdifjoOc%]", "g"),
    (r"\{\{\s*(\w+)\s*\}\}", "g"),
    (r"[&<>'\x22]", "g"),
    (r"^\[object (\w+)\]$", ""),
    (r"(?:^|\s)foo(?=\s|$)", ""),
    (r"^(?<year>\d{4})-(?<month>\d{2})$", "u"),
    (r"\r\n?|\n", "g"),
    (r"[\x00-\x1f\x7f]", "g"),
    (r"^[A-Za-z0-9+/]*={0,2}$", ""),
    (r"(\d)(?=(\d{3})+(?!\d))", "g"),
    (r"^\p{Lu}\p{Ll}+$", "u"),
    (r"[\u{1F300}-\u{1FAFF}]", "gu"),
    (r"(?<!\\)\$\{([^}]+)\}", "g"),
    (r"\bclass\s+(\w+)", "m"),
];

/// Deterministic pseudo-random patterns built from regex fragments, to reach
/// combinations the hand-picked cases miss.
fn random_cases(count: usize) -> Vec<(String, String)> {
    const PIECES: &[&str] = &[
        "a",
        "b",
        "Z",
        "\u{e9}",
        "\u{17F}",
        "\u{1F600}",
        r"\d",
        r"\w",
        r"\s",
        r"\W",
        r"\b",
        r"\B",
        ".",
        "^",
        "$",
        "(",
        ")",
        "(?:",
        "(?=",
        "(?!",
        "(?<=",
        "(?<!",
        "(?<n>",
        "[",
        "]",
        "[^",
        "-",
        "|",
        "*",
        "+",
        "?",
        "*?",
        "{2}",
        "{1,3}",
        "{2,}",
        r"\1",
        r"\2",
        r"\k<n>",
        r"A",
        r"\u{1F600}",
        r"\x41",
        r"\p{L}",
        r"\P{Lu}",
        r"\cA",
        r"\0",
        "{",
        "}",
        "k",
        r"\uD83D",
        r"\-",
        "A-Z",
        "0-9",
    ];
    const FLAGS: &[&str] = &["", "i", "u", "iu", "m", "s", "su", "g", "y", "ims", "isu"];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = |bound: usize| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((state >> 33) as usize) % bound
    };
    (0..count)
        .map(|_| {
            let length = 1 + next(8);
            let pattern: String = (0..length).map(|_| PIECES[next(PIECES.len())]).collect();
            (pattern, FLAGS[next(FLAGS.len())].to_string())
        })
        .collect()
}

/// Deterministic pseudo-random patterns from a small regex grammar; unlike
/// `random_cases` these are mostly valid, so they reach the emitter.
fn grammar_cases(count: usize) -> Vec<(String, String)> {
    const FLAGS: &[&str] = &["", "i", "u", "iu", "m", "s", "su", "ims", "imsu", "g"];
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    (0..count)
        .map(|_| {
            let pattern = alternation(&mut next, 3);
            (pattern, FLAGS[next(FLAGS.len())].to_string())
        })
        .collect()
}

fn alternation(next: &mut dyn FnMut(usize) -> usize, depth: usize) -> String {
    let count = 1 + usize::from(next(4) == 0) + usize::from(next(8) == 0);
    (0..count)
        .map(|_| sequence(next, depth))
        .collect::<Vec<_>>()
        .join("|")
}

fn sequence(next: &mut dyn FnMut(usize) -> usize, depth: usize) -> String {
    const ATOMS: &[&str] = &[
        "a",
        "b",
        "q",
        "Z",
        "_",
        "0",
        "\u{e9}",
        "\u{3a3}",
        "\u{17f}",
        "\u{1F600}",
        ".",
        r"\d",
        r"\D",
        r"\w",
        r"\s",
        r"\S",
        "[a-z]",
        "[^a-z]",
        r"[\d_]",
        "[A-Z\u{e9}]",
        r"[\w-]",
        "[\u{1F600}-\u{1F64F}]",
        r"\x41",
        r"B",
        r"\t",
        r"\.",
        r"\$",
        "^",
        "$",
        r"\b",
        r"\B",
        r"\1",
        "abc",
        "abcdefgh",
        "\u{e9}\u{e8}",
        r"\p{Lu}",
        r"[\p{N}x]",
        r"\P{L}",
        "K",
        "k",
    ];
    const QUANTIFIERS: &[&str] = &[
        "", "", "", "*", "+", "?", "*?", "+?", "{2}", "{1,4}", "{0,}", "{3}?",
    ];
    const OPENERS: &[&str] = &["(", "(?:", "(?=", "(?!", "(?<=", "(?<!", "(?<g>"];
    (0..1 + next(4))
        .map(|_| {
            let atom = if depth > 0 && next(4) == 0 {
                let open = OPENERS[next(OPENERS.len())];
                format!("{open}{})", alternation(next, depth - 1))
            } else {
                ATOMS[next(ATOMS.len())].to_string()
            };
            format!("{atom}{}", QUANTIFIERS[next(QUANTIFIERS.len())])
        })
        .collect()
}

/// What hermesc makes of /pattern/flags: Some(Ok(bytecode)), Some(Err(message))
/// for a pattern it rejects, or None if it can't lex the literal at all.
fn hermesc(hermesc: &str, pattern: &str, flags: &str) -> Option<Result<Vec<u8>, String>> {
    // `/*` starts a comment, not a literal.
    if pattern.starts_with('*') {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("case.js");
    let output = dir.path().join("case.hbc");
    fs::write(&source, format!("var r = /{pattern}/{flags};\n")).unwrap();
    let run = Command::new(hermesc)
        .args(["-emit-binary", "-out"])
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    if !run.status.success() {
        let stderr = String::from_utf8_lossy(&run.stderr);
        let message = stderr
            .lines()
            .find_map(|line| line.split_once("error: Invalid regular expression: "))?
            .1;
        return Some(Err(message.to_string()));
    }
    let bytes = fs::read(&output).unwrap();
    let spec = load_spec(96).unwrap();
    let container = parse_hbc_container_with_spec(&bytes, &spec.container).unwrap();
    assert_eq!(container.reg_exp_entries.len(), 1, "/{pattern}/{flags}");
    let entry = &container.reg_exp_entries[0];
    let start = entry.first as usize;
    Some(Ok(container.reg_exp_storage
        [start..start + entry.second as usize]
        .to_vec()))
}

#[test]
#[ignore = "requires HERMESC_BIN for an HBC 96 compiler; rewrites the fixture"]
fn regenerate_hermesc_fixture() {
    let binary = std::env::var("HERMESC_BIN").expect("set HERMESC_BIN to an HBC 96 hermesc");
    let mut cases: Vec<(String, String)> = CASES
        .iter()
        .map(|&(pattern, flags)| (pattern.to_string(), flags.to_string()))
        .collect();
    let hand_picked = cases.len();
    cases.extend(random_cases(1500));
    cases.extend(grammar_cases(2500));
    let mut seen = std::collections::HashSet::new();
    // Most generated patterns are invalid; keep enough of each error.
    let mut errors_seen = std::collections::HashMap::new();
    let mut lines = Vec::new();
    for (index, (pattern, flags)) in cases.into_iter().enumerate() {
        if !seen.insert((pattern.clone(), flags.clone())) {
            continue;
        }
        let Some(result) = hermesc(&binary, &pattern, &flags) else {
            continue;
        };
        let line = match result {
            Ok(bytecode) => {
                json!({ "pattern": pattern, "flags": flags, "bytecode": summary(&bytecode) })
            }
            Err(error) => {
                let count: &mut usize = errors_seen.entry(error.clone()).or_default();
                *count += 1;
                if index >= hand_picked && *count > 40 {
                    continue;
                }
                json!({ "pattern": pattern, "flags": flags, "error": error })
            }
        };
        lines.push(line.to_string());
    }
    fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
    fs::write(fixture_path(), lines.join("\n") + "\n").unwrap();
}

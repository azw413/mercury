use mercury_asm::{parse_semantic_assembly, raise_module};
use mercury_binary::DecodedOperand;
use mercury_spec_builtin::load_spec;

fn raise(body: &str) -> Result<mercury_asm::RaisedAssemblyModule, mercury_asm::RaiseError> {
    let source =
        format!("bytecode_version 96\n.function @f params=1 frame=3 env=0\n{body}\n.end\n");
    raise_module(
        &parse_semantic_assembly(&source).unwrap(),
        &load_spec(96).unwrap().bytecode,
    )
}

#[test]
fn rejects_operands_that_would_be_truncated_or_discarded() {
    for body in [
        "return r256",
        "load_param r0, -1",
        "get_by_id r0, r1, 256, \"x\"",
        "return r0, r1",
        "return",
        "load_immediate r0, undefined, 3",
        "load_immediate r0, 9007199254740993",
        "load_param r0, 4294967296",
    ] {
        assert!(raise(body).is_err(), "accepted invalid assembly: {body}");
    }
}

#[test]
fn rejects_ambiguous_symbols() {
    assert!(raise("L1:\nreturn r0\nL1:\nreturn r0").is_err());
    let source = ".function @f params=1 frame=1 env=0\nreturn r0\n.end\n".repeat(2);
    assert!(
        raise_module(
            &parse_semantic_assembly(&source).unwrap(),
            &load_spec(96).unwrap().bytecode
        )
        .is_err()
    );
}

#[test]
fn branch_targets_follow_edits_despite_stale_display_offsets() {
    let body = format!(
        "0000: branch Lend\n0002: load_immediate r0, 0\n{}Lend:\n0003: return r0",
        "load_immediate r0, 1\n".repeat(100)
    );
    let raised = raise(&body).unwrap();
    let instructions = &raised.functions[0].instructions;
    let target = instructions.last().unwrap().offset;
    assert_eq!(
        instructions[0].operands,
        vec![DecodedOperand::I32(target as i32)]
    );
    let without_offsets = body
        .replace("0000: ", "")
        .replace("0002: ", "")
        .replace("0003: ", "");
    assert_eq!(raised, raise(&without_offsets).unwrap());
}

#[test]
fn backward_branches_and_boundary_values_remain_exact() {
    let raised = raise("Lstart:\nload_param r255, 255\nbranch Lstart").unwrap();
    let instructions = &raised.functions[0].instructions;
    assert_eq!(
        instructions[0].operands,
        vec![DecodedOperand::U8(255), DecodedOperand::U8(255)]
    );
    assert_eq!(
        instructions[1].operands,
        vec![DecodedOperand::I32(-(instructions[1].offset as i32))]
    );
    assert!(raise("load_const_string r0, 65536").is_err());
    assert!(raise("branch Lend\nLend:").is_err());
}

#[test]
fn parser_rejects_malformed_text_instead_of_ignoring_it() {
    for source in [
        "bytecode_version nope",
        "bytecode_version 96\nbytecode_version 94",
        ".function @f params=1 frame=1 env=0 mystery=1\n.end",
        ".function @f params=1 frame=1 frame=2 env=0\n.end",
        ".function @f params=1 frame=1 env=0\nreturn r0,\n.end",
        ".function @f params=1 frame=1 env=0\nmove r0,,r1\n.end",
    ] {
        assert!(
            parse_semantic_assembly(source).is_err(),
            "accepted {source}"
        );
    }
}

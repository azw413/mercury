use mercury_swc::{
    Error, HermesCompiler, SourceKind, SourceLanguage, SwcModule,
    ast::*,
    visit::{Visit, VisitMut, VisitMutWith, VisitWith},
};

#[test]
fn source_roundtrip_preserves_comments_and_shadowed_bindings() {
    let text =
        "// keep me\nlet value = 1; function f(value) { return value + 1; } print(value, f(2));";
    let mut module = SwcModule::parse(
        "test.js",
        text,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    // Identifier contexts distinguish the outer binding from the parameter.
    struct Gather(Vec<mercury_swc::swc_core::common::SyntaxContext>);
    impl Visit for Gather {
        fn visit_ident(&mut self, id: &Ident) {
            if id.sym == *"value" {
                self.0.push(id.ctxt);
            }
        }
    }
    let mut gather = Gather(vec![]);
    module.with_ast(|program| program.visit_with(&mut gather));
    assert!(gather.0.iter().any(|ctxt| *ctxt != gather.0[0]));
    let printed = module.print();
    assert!(printed.contains("// keep me"));
    SwcModule::parse(
        "again.js",
        &printed,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
}

#[test]
fn typescript_is_preserved_for_printing_and_lowered_for_execution() {
    let module = SwcModule::parse(
        "test.ts",
        "enum Mode { A = 4 } const x: number = Mode.A; print(x);",
        SourceLanguage::TypeScript,
        SourceKind::Script,
    )
    .unwrap();
    assert!(module.print().contains(": number"));
    let js = module.javascript();
    assert!(!js.contains("enum Mode"));
    assert!(!js.contains(": number"));
    SwcModule::parse(
        "lowered.js",
        &js,
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    assert!(
        module.print().contains("enum Mode"),
        "lowering must not consume the original tree"
    );
}

#[test]
fn visitor_edits_real_swc_nodes() {
    struct Edit;
    impl VisitMut for Edit {
        fn visit_mut_number(&mut self, n: &mut Number) {
            n.value += 1.0;
            n.raw = None;
        }
    }
    let mut module = SwcModule::parse(
        "edit.js",
        "print(1);",
        SourceLanguage::JavaScript,
        SourceKind::Script,
    )
    .unwrap();
    module.with_ast(|p| p.visit_mut_with(&mut Edit));
    assert!(module.print().contains("print(2)"));
}

#[test]
fn syntax_errors_include_location_and_modules_do_not_silently_become_scripts() {
    for source in ["let x = ;", "const x;"] {
        let err = SwcModule::parse(
            "bad.js",
            source,
            SourceLanguage::JavaScript,
            SourceKind::Script,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("bad.js:1:"));
    }
    let module = SwcModule::parse(
        "esm.js",
        "export const x = 1;",
        SourceLanguage::JavaScript,
        SourceKind::Module,
    )
    .unwrap();
    assert!(matches!(
        HermesCompiler::new("not-invoked", 96).compile(&module),
        Err(Error::Unsupported(_))
    ));
}

use crate::Error;
use swc_core::{
    common::{
        FileName, GLOBALS, Globals, Mark, SourceMap, Spanned, comments::SingleThreadedComments,
        sync::Lrc,
    },
    ecma::{
        ast::{EsVersion, Pass, Program},
        codegen::to_code_default,
        parser::{Parser, StringInput, Syntax, TsSyntax, lexer::Lexer},
        transforms::{
            base::{fixer::fixer, hygiene::hygiene, resolver},
            typescript::strip,
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    JavaScript,
    TypeScript,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Script,
    Module,
}

/// A real SWC tree plus the context needed by SWC passes and code generation.
/// Use `transform` for SWC passes, or `with_ast` to edit/inspect binding contexts.
/// Generated identifiers must be fresh or carry the intended existing context.
pub struct SwcModule {
    pub program: Program,
    pub comments: SingleThreadedComments,
    pub source_map: Lrc<SourceMap>,
    globals: Globals,
    unresolved: Mark,
    top_level: Mark,
    language: SourceLanguage,
}

impl SwcModule {
    pub fn parse(
        name: &str,
        text: &str,
        language: SourceLanguage,
        kind: SourceKind,
    ) -> Result<Self, Error> {
        let source_map: Lrc<SourceMap> = Default::default();
        let comments = SingleThreadedComments::default();
        let file =
            source_map.new_source_file(FileName::Custom(name.into()).into(), text.to_owned());
        let syntax = match language {
            SourceLanguage::JavaScript => Syntax::Es(Default::default()),
            SourceLanguage::TypeScript => Syntax::Typescript(TsSyntax::default()),
        };
        let lexer = Lexer::new(
            syntax,
            EsVersion::latest(),
            StringInput::from(&*file),
            Some(&comments),
        );
        let mut parser = Parser::new_from(lexer);
        let result = match kind {
            SourceKind::Script => parser.parse_script().map(Program::Script),
            SourceKind::Module => parser.parse_module().map(Program::Module),
        };
        let mut errors = parser.take_errors();
        let mut program = match result {
            Ok(program) => Some(program),
            Err(err) => {
                errors.push(err);
                None
            }
        };
        if !errors.is_empty() {
            return Err(Error::Parse(
                errors
                    .iter()
                    .map(|err| {
                        let pos = source_map.lookup_char_pos(err.span().lo);
                        format!(
                            "{name}:{}:{}: {}",
                            pos.line,
                            pos.col_display + 1,
                            err.kind().msg()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
        }
        let globals = Globals::default();
        let (unresolved, top_level) = GLOBALS.set(&globals, || {
            let marks = (Mark::new(), Mark::new());
            program.as_mut().expect("successful parse").mutate(resolver(
                marks.0,
                marks.1,
                language == SourceLanguage::TypeScript,
            ));
            marks
        });
        Ok(Self {
            program: program.expect("successful parse"),
            comments,
            source_map,
            globals,
            unresolved,
            top_level,
            language,
        })
    }

    pub(crate) fn generated(program: Program) -> Self {
        let globals = Globals::default();
        let mut program = program;
        let (unresolved, top_level) = GLOBALS.set(&globals, || {
            let marks = (Mark::new(), Mark::new());
            program.mutate(resolver(marks.0, marks.1, false));
            marks
        });
        Self {
            program,
            comments: Default::default(),
            source_map: Default::default(),
            globals,
            unresolved,
            top_level,
            language: SourceLanguage::JavaScript,
        }
    }

    pub fn with_ast<R>(&mut self, edit: impl FnOnce(&mut Program) -> R) -> R {
        GLOBALS.set(&self.globals, || edit(&mut self.program))
    }

    pub fn transform(&mut self, pass: impl Pass) {
        self.with_ast(|program| program.mutate(pass));
    }

    /// Prints the current tree, retaining TypeScript syntax when present.
    pub fn print(&self) -> String {
        GLOBALS.set(&self.globals, || {
            let program = self
                .program
                .clone()
                .apply(hygiene())
                .apply(fixer(Some(&self.comments)));
            to_code_default(self.source_map.clone(), Some(&self.comments), &program)
        })
    }

    /// Lowers TS runtime constructs and removes types on a copy of the tree.
    /// This is transpilation, not TypeScript type checking or ESM bundling.
    pub fn javascript(&self) -> String {
        GLOBALS.set(&self.globals, || {
            let mut program = self.program.clone();
            if self.language == SourceLanguage::TypeScript {
                program.mutate(strip(self.unresolved, self.top_level));
            }
            program.mutate(hygiene());
            program.mutate(fixer(Some(&self.comments)));
            to_code_default(self.source_map.clone(), Some(&self.comments), &program)
        })
    }
}

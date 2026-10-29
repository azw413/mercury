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

/// The source syntax used to parse a [`SwcModule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    /// Parse standard JavaScript, including ECMAScript proposals accepted by SWC.
    JavaScript,
    /// Parse TypeScript annotations and runtime constructs such as enums.
    TypeScript,
}

/// The goal used when parsing source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// Parse a classic script, suitable for native HBC compilation.
    Script,
    /// Parse an ECMAScript module with `import` and `export` declarations.
    Module,
}

/// A real SWC tree together with its comments, source map, and binding contexts.
///
/// Values returned by [`parse`](Self::parse) have already run SWC's resolver.
/// Use [`with_ast`](Self::with_ast) for visitor-based edits or
/// [`transform`](Self::transform) for an SWC pass so operations run with the
/// correct [`Globals`](swc_core::common::Globals). Generated identifiers must be
/// fresh or carry the intended existing syntax context.
pub struct SwcModule {
    /// The parsed script or module, including any subsequent edits.
    pub program: Program,
    /// Comments captured by the parser and retained during code generation.
    pub comments: SingleThreadedComments,
    /// Source files and locations used for diagnostics and printing.
    pub source_map: Lrc<SourceMap>,
    globals: Globals,
    unresolved: Mark,
    top_level: Mark,
    language: SourceLanguage,
    generated: bool,
}

impl SwcModule {
    /// Parses JavaScript or TypeScript and resolves its binding contexts.
    ///
    /// `name` is used in diagnostics and does not need to name an existing file.
    /// Comments are retained for printing. TypeScript syntax is preserved until
    /// [`javascript`](Self::javascript) or native HBC compilation requests lowering.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] with filename, line, and column diagnostics when
    /// SWC reports fatal or recoverable syntax errors.
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
            generated: false,
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
            generated: true,
        }
    }

    /// Runs `edit` on the program with this module's SWC globals installed.
    ///
    /// This is the general escape hatch for inspection and visitor-based mutation.
    /// The closure's return value is forwarded unchanged. Prefer this method over
    /// accessing [`program`](Self::program) directly when creating or resolving
    /// identifiers, since SWC operations may depend on thread-local globals.
    pub fn with_ast<R>(&mut self, edit: impl FnOnce(&mut Program) -> R) -> R {
        GLOBALS.set(&self.globals, || edit(&mut self.program))
    }

    /// Applies an SWC pass to the program in the module's binding context.
    pub fn transform(&mut self, pass: impl Pass) {
        self.with_ast(|program| program.mutate(pass));
    }

    /// Prints the current tree with comments, retaining TypeScript syntax.
    ///
    /// This method does not mutate the module. Exporting a generated source map is
    /// not currently implemented.
    pub fn print(&self) -> String {
        GLOBALS.set(&self.globals, || {
            // Decompiler builders produce emission-ready nodes and namespace
            // every generated binding. Re-running hygiene and fixer here would
            // clone and traverse multi-million-node bundle ASTs needlessly.
            if self.generated {
                return to_code_default(
                    self.source_map.clone(),
                    Some(&self.comments),
                    &self.program,
                );
            }
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
            // Generated modules are JavaScript and already satisfy the emitter
            // invariants maintained by the decompiler's AST builders.
            if self.generated {
                return to_code_default(
                    self.source_map.clone(),
                    Some(&self.comments),
                    &self.program,
                );
            }
            let mut program = self.program.clone();
            if self.language == SourceLanguage::TypeScript {
                program.mutate(strip(self.unresolved, self.top_level));
            }
            program.mutate(hygiene());
            program.mutate(fixer(Some(&self.comments)));
            to_code_default(self.source_map.clone(), Some(&self.comments), &program)
        })
    }

    /// Returns a JavaScript AST suitable for consumers that lower trees
    /// directly. TypeScript syntax is removed without printing and reparsing.
    pub(crate) fn javascript_program(&self) -> Program {
        GLOBALS.set(&self.globals, || {
            let mut program = self.program.clone();
            if self.language == SourceLanguage::TypeScript {
                program.mutate(strip(self.unresolved, self.top_level));
            }
            program
        })
    }
}

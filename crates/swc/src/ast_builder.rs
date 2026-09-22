//! Small internal constructors; bytecode lowering creates SWC nodes directly.
#![allow(clippy::vec_box)] // SWC's child-expression fields are boxed.

use swc_core::{
    common::{DUMMY_SP, SyntaxContext},
    ecma::ast::*,
};
pub fn ident(name: &str) -> Ident {
    Ident::new(name.into(), DUMMY_SP, SyntaxContext::empty())
}
pub fn id(name: &str) -> Box<Expr> {
    Box::new(Expr::Ident(ident(name)))
}
pub fn number(value: f64) -> Box<Expr> {
    Box::new(Expr::Lit(Lit::Num(Number {
        span: DUMMY_SP,
        value,
        raw: None,
    })))
}
pub fn string(value: &str) -> Box<Expr> {
    Box::new(Expr::Lit(Lit::Str(Str {
        span: DUMMY_SP,
        value: value.into(),
        raw: None,
    })))
}
pub fn boolean(value: bool) -> Box<Expr> {
    Box::new(Expr::Lit(Lit::Bool(Bool {
        span: DUMMY_SP,
        value,
    })))
}
pub fn undefined() -> Box<Expr> {
    unary(UnaryOp::Void, number(0.0))
}
pub fn unary(op: UnaryOp, arg: Box<Expr>) -> Box<Expr> {
    Box::new(Expr::Unary(UnaryExpr {
        span: DUMMY_SP,
        op,
        arg,
    }))
}
pub fn binary(op: BinaryOp, left: Box<Expr>, right: Box<Expr>) -> Box<Expr> {
    Box::new(Expr::Bin(BinExpr {
        span: DUMMY_SP,
        op,
        left,
        right,
    }))
}
pub fn member(obj: Box<Expr>, key: Box<Expr>) -> Box<Expr> {
    Box::new(Expr::Member(MemberExpr {
        span: DUMMY_SP,
        obj,
        prop: MemberProp::Computed(ComputedPropName {
            span: DUMMY_SP,
            expr: key,
        }),
    }))
}
pub fn call(callee: Box<Expr>, args: Vec<Box<Expr>>) -> Box<Expr> {
    Box::new(Expr::Call(CallExpr {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        callee: Callee::Expr(callee),
        args: args
            .into_iter()
            .map(|expr| ExprOrSpread { spread: None, expr })
            .collect(),
        type_args: None,
    }))
}
pub fn expr(expr: Box<Expr>) -> Stmt {
    Stmt::Expr(ExprStmt {
        span: DUMMY_SP,
        expr,
    })
}
pub fn assign(left: Box<Expr>, right: Box<Expr>) -> Stmt {
    expr(Box::new(Expr::Assign(AssignExpr {
        span: DUMMY_SP,
        op: AssignOp::Assign,
        left: left.try_into().expect("generated assignable expression"),
        right,
    })))
}
pub fn block(stmts: Vec<Stmt>) -> BlockStmt {
    BlockStmt {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        stmts,
    }
}
pub fn ret(value: Box<Expr>) -> Stmt {
    Stmt::Return(ReturnStmt {
        span: DUMMY_SP,
        arg: Some(value),
    })
}
pub fn var(name: &str, init: Option<Box<Expr>>) -> Stmt {
    Stmt::Decl(Decl::Var(Box::new(VarDecl {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        kind: VarDeclKind::Var,
        declare: false,
        decls: vec![VarDeclarator {
            span: DUMMY_SP,
            name: Pat::Ident(ident(name).into()),
            init,
            definite: false,
        }],
    })))
}
pub fn function(name: Option<&str>, params: Vec<String>, body: Vec<Stmt>) -> Box<Expr> {
    Box::new(Expr::Fn(FnExpr {
        ident: name.map(ident),
        function: Box::new(Function {
            params: params
                .iter()
                .map(|name| Param {
                    span: DUMMY_SP,
                    decorators: vec![],
                    pat: Pat::Ident(ident(name).into()),
                })
                .collect(),
            decorators: vec![],
            span: DUMMY_SP,
            ctxt: SyntaxContext::empty(),
            body: Some(block(body)),
            is_generator: false,
            is_async: false,
            type_params: None,
            return_type: None,
        }),
    }))
}
pub fn array(values: Vec<Box<Expr>>) -> Box<Expr> {
    Box::new(Expr::Array(ArrayLit {
        span: DUMMY_SP,
        elems: values
            .into_iter()
            .map(|expr| Some(ExprOrSpread { spread: None, expr }))
            .collect(),
    }))
}
pub fn this() -> Box<Expr> {
    Box::new(Expr::This(ThisExpr { span: DUMMY_SP }))
}

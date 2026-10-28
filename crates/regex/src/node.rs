//! The regex syntax tree and its bytecode emitter, ported from Hermes's
//! `RegexNode.h`. Nodes live in an arena and lists of nodes refer to them by
//! index, standing in for Hermes's node pointers.

use crate::flags::SyntaxFlags;
use crate::unicode::{
    CodePointSet, is_high_surrogate, is_low_surrogate, make_canonically_equivalent,
};

pub type NodeId = usize;
pub type NodeList = Vec<NodeId>;

/// Match constraints: facts that let the executor skip impossible inputs.
pub const NON_ASCII: u8 = 1 << 0;
pub const ANCHORED_AT_START: u8 = 1 << 1;
pub const NON_EMPTY: u8 = 1 << 2;

/// Character classes, as stored in a bracket instruction's class bitmasks.
pub const DIGITS: u8 = 1 << 0;
pub const SPACES: u8 = 1 << 1;
pub const WORDS: u8 = 1 << 2;

/// Regex bytecode opcodes, numbered as in Hermes's `RegexOpcodes.def`.
mod op {
    pub const GOAL: u8 = 0;
    pub const LEFT_ANCHOR: u8 = 1;
    pub const RIGHT_ANCHOR: u8 = 2;
    pub const MATCH_ANY: u8 = 3;
    pub const U16_MATCH_ANY: u8 = 4;
    pub const MATCH_ANY_BUT_NEWLINE: u8 = 5;
    pub const U16_MATCH_ANY_BUT_NEWLINE: u8 = 6;
    pub const MATCH_CHAR8: u8 = 7;
    pub const MATCH_CHAR16: u8 = 8;
    pub const U16_MATCH_CHAR32: u8 = 9;
    pub const MATCH_N_CHAR8: u8 = 10;
    pub const MATCH_N_CHAR_ICASE8: u8 = 11;
    pub const MATCH_CHAR_ICASE8: u8 = 12;
    pub const MATCH_CHAR_ICASE16: u8 = 13;
    pub const U16_MATCH_CHAR_ICASE32: u8 = 14;
    pub const ALTERNATION: u8 = 15;
    pub const JUMP32: u8 = 16;
    pub const BRACKET: u8 = 17;
    pub const U16_BRACKET: u8 = 18;
    pub const BEGIN_MARKED_SUBEXPRESSION: u8 = 19;
    pub const END_MARKED_SUBEXPRESSION: u8 = 20;
    pub const BACK_REF: u8 = 21;
    pub const WORD_BOUNDARY: u8 = 22;
    pub const LOOKAROUND: u8 = 23;
    pub const BEGIN_LOOP: u8 = 24;
    pub const END_LOOP: u8 = 25;
    pub const BEGIN_SIMPLE_LOOP: u8 = 26;
    pub const END_SIMPLE_LOOP: u8 = 27;
    pub const WIDTH1_LOOP: u8 = 28;
}

/// The bytecode header: marked count, loop count, flags, constraints.
pub const HEADER_SIZE: usize = 6;

/// MatchChar emits runs of at least this many ASCII characters as MatchNChar8.
const MIN_MATCH_N_CHAR_COUNT: usize = 3;
const MAX_MATCH_N_CHAR_COUNT: usize = u8::MAX as usize;

#[derive(Debug, Clone, Copy)]
pub struct CharacterClass {
    pub kind: u8,
    pub inverted: bool,
}

#[derive(Debug)]
pub struct Bracket {
    pub set: CodePointSet,
    pub classes: Vec<CharacterClass>,
    negate: bool,
    icase: bool,
    unicode: bool,
}

impl Bracket {
    fn can_match_ascii(&self) -> bool {
        // Non-ASCII characters only canonicalize to ASCII under /iu.
        if self.icase && self.unicode {
            return true;
        }
        if self.negate {
            !self
                .set
                .ranges()
                .iter()
                .any(|range| range.first == 0 && range.length > 127)
        } else {
            !self.classes.is_empty() || self.set.ranges().iter().any(|range| range.first <= 127)
        }
    }
}

#[derive(Debug)]
pub enum Node {
    /// Matches the empty string; every node list starts with one.
    Empty,
    Goal,
    Loop {
        loop_id: u32,
        min: u32,
        max: u32,
        mexp_begin: u16,
        mexp_end: u16,
        greedy: bool,
        loopee: NodeList,
        loopee_constraints: u8,
    },
    Alternation {
        alternatives: Vec<NodeList>,
        /// Constraints of each alternative.
        element: Vec<u8>,
        /// `rest[i]`: constraints common to alternatives `i..`.
        rest: Vec<u8>,
    },
    MarkedSubexpression {
        contents: NodeList,
        contents_constraints: u8,
        mexp: u16,
    },
    BackRef {
        mexp: u16,
    },
    WordBoundary {
        invert: bool,
    },
    LeftAnchor {
        multiline: bool,
    },
    RightAnchor,
    MatchAny {
        unicode: bool,
        dot_all: bool,
    },
    MatchChar {
        chars: Vec<u32>,
        icase: bool,
        unicode: bool,
    },
    Bracket(Bracket),
    Lookaround {
        exp: NodeList,
        exp_constraints: u8,
        invert: bool,
        forwards: bool,
        mexp_begin: u16,
        mexp_end: u16,
    },
}

/// Whether matching `cp` may mean decoding a surrogate pair from the input.
fn may_require_surrogate_pair(cp: u32, unicode: bool) -> bool {
    // A literal lone surrogate under /u only matches an unpaired surrogate,
    // so it too needs the decoding (32-bit) instruction.
    cp > 0xFFFF || (unicode && (is_high_surrogate(cp) || is_low_surrogate(cp)))
}

impl Node {
    pub fn new_bracket(negate: bool, flags: SyntaxFlags) -> Self {
        Self::Bracket(Bracket {
            set: CodePointSet::default(),
            classes: Vec::new(),
            negate,
            icase: flags.ignore_case,
            unicode: flags.unicode,
        })
    }
}

#[derive(Default)]
pub struct Arena {
    nodes: Vec<Node>,
}

impl Arena {
    pub fn push(&mut self, node: Node) -> NodeId {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    pub fn get_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id]
    }

    pub fn bracket_mut(&mut self, id: NodeId) -> &mut Bracket {
        match &mut self.nodes[id] {
            Node::Bracket(bracket) => bracket,
            _ => unreachable!("node {id} is not a bracket"),
        }
    }

    pub fn constraints(&self, id: NodeId) -> u8 {
        match &self.nodes[id] {
            Node::Empty
            | Node::Goal
            | Node::BackRef { .. }
            | Node::WordBoundary { .. }
            | Node::RightAnchor => 0,
            Node::Loop {
                min,
                loopee_constraints,
                ..
            } => {
                if *min > 0 {
                    *loopee_constraints
                } else {
                    0
                }
            }
            Node::Alternation { rest, .. } => rest[0],
            Node::MarkedSubexpression {
                contents_constraints,
                ..
            } => *contents_constraints,
            Node::LeftAnchor { multiline } => {
                if *multiline {
                    0
                } else {
                    ANCHORED_AT_START
                }
            }
            Node::MatchAny { .. } => NON_EMPTY,
            Node::MatchChar { chars, .. } => {
                if chars.iter().all(|&c| c <= 127) {
                    NON_EMPTY
                } else {
                    NON_EMPTY | NON_ASCII
                }
            }
            Node::Bracket(bracket) => {
                let mut result = 0;
                if !bracket.can_match_ascii() {
                    result |= NON_ASCII;
                }
                if !(bracket.set.ranges().is_empty() && bracket.classes.is_empty()) {
                    result |= NON_EMPTY;
                }
                result
            }
            Node::Lookaround {
                exp_constraints,
                invert,
                ..
            } => {
                // Lookarounds match the empty string even if their contents
                // don't, and only positive ones pass their constraints on.
                (if *invert { 0 } else { *exp_constraints }) & !NON_EMPTY
            }
        }
    }

    pub fn constraints_for_list(&self, list: &[NodeId]) -> u8 {
        list.iter().fold(0, |acc, &id| acc | self.constraints(id))
    }

    fn matches_exactly_one_character(&self, id: NodeId) -> bool {
        match &self.nodes[id] {
            // Under /u these may match a surrogate pair.
            Node::MatchAny { unicode, .. } => !unicode,
            Node::Bracket(bracket) => !bracket.unicode,
            Node::MatchChar { chars, unicode, .. } => {
                chars.len() == 1 && !may_require_surrogate_pair(chars[0], *unicode)
            }
            _ => false,
        }
    }

    /// Reverse `list` (keeping a trailing goal last) and, recursively, the
    /// children of its nodes, for lookbehinds which match right to left.
    pub fn reverse_list(&mut self, list: &mut NodeList) {
        let has_goal = list
            .last()
            .is_some_and(|&id| matches!(self.nodes[id], Node::Goal));
        let len = list.len() - usize::from(has_goal);
        list[..len].reverse();
        for &id in list.iter() {
            self.reverse_children(id);
        }
    }

    fn reverse_children(&mut self, id: NodeId) {
        match &mut self.nodes[id] {
            Node::MatchChar { chars, .. } => chars.reverse(),
            // Lookarounds keep their own direction.
            Node::Lookaround { .. } => {}
            _ => {
                for index in 0..self.child_lists_mut(id).len() {
                    let mut list = std::mem::take(self.child_lists_mut(id)[index]);
                    self.reverse_list(&mut list);
                    *self.child_lists_mut(id)[index] = list;
                }
            }
        }
    }

    fn child_lists_mut(&mut self, id: NodeId) -> Vec<&mut NodeList> {
        match &mut self.nodes[id] {
            Node::Loop { loopee, .. } => vec![loopee],
            Node::Alternation { alternatives, .. } => alternatives.iter_mut().collect(),
            Node::MarkedSubexpression { contents, .. } => vec![contents],
            Node::Lookaround { exp, .. } => vec![exp],
            _ => Vec::new(),
        }
    }

    /// Merge runs of adjacent MatchChar nodes into one.
    ///
    /// This mirrors Hermes exactly, including a quirk: after a run the node
    /// that ended it is skipped, so lists nested inside it are never visited.
    pub fn optimize(&mut self, root: &mut NodeList, flags: SyntaxFlags) {
        // Each entry is a list to optimize: the root, or a node's nth child list.
        let mut stack: Vec<Option<(NodeId, usize)>> = vec![None];
        while let Some(location) = stack.pop() {
            let mut list = match location {
                None => std::mem::take(root),
                Some((id, index)) => std::mem::take(self.child_lists_mut(id)[index]),
            };
            let mut merged: Vec<Option<NodeId>> = list.iter().copied().map(Some).collect();
            let max = list.len();
            let mut index = 0;
            while index < max {
                let children = self.child_lists_mut(list[index]).len();
                stack.extend((0..children).map(|child| Some((list[index], child))));
                let mut chars = Vec::new();
                let run_start = index;
                while index < max {
                    match &self.nodes[list[index]] {
                        Node::MatchChar { chars: more, .. } => chars.extend_from_slice(more),
                        _ => break,
                    }
                    index += 1;
                }
                if index - run_start >= 2 {
                    let node = self.push(Node::MatchChar {
                        chars,
                        icase: flags.ignore_case,
                        unicode: flags.unicode,
                    });
                    merged[run_start] = Some(node);
                    merged[run_start + 1..index].fill(None);
                }
                index += 1;
            }
            list = merged.into_iter().flatten().collect();
            match location {
                None => *root = list,
                Some((id, index)) => *self.child_lists_mut(id)[index] = list,
            }
        }
    }

    /// Append the bytecode for `nodes` to `out`, which already holds the
    /// header; jump targets are offsets past the header.
    pub fn emit(&self, nodes: &[NodeId], out: &mut Vec<u8>) {
        Emitter {
            arena: self,
            out,
            alternations: Vec::new(),
        }
        .run(nodes);
    }
}

enum Task {
    Node(NodeId),
    EndMarked(u16),
    EndLookaround {
        insn: usize,
    },
    EndWidth1Loop {
        insn: usize,
    },
    EndSimpleLoop {
        insn: usize,
        entry: u32,
    },
    EndLoop {
        insn: usize,
        entry: u32,
    },
    /// Start alternative `index` of the alternation whose state is `state`.
    AlternativeHeader {
        state: usize,
        primary: u8,
        secondary: u8,
    },
    /// Jump from the end of a non-final alternative to after the alternation.
    AlternativeJump {
        state: usize,
    },
    EndAlternation {
        state: usize,
    },
}

#[derive(Default)]
struct AlternationState {
    /// The Alternation instruction whose secondary branch is pending.
    header: usize,
    jumps: Vec<usize>,
}

struct Emitter<'a> {
    arena: &'a Arena,
    out: &'a mut Vec<u8>,
    alternations: Vec<AlternationState>,
}

impl Emitter<'_> {
    fn offset(&self) -> u32 {
        (self.out.len() - HEADER_SIZE) as u32
    }

    fn patch_u32(&mut self, at: usize, value: u32) {
        self.out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    fn run(&mut self, nodes: &[NodeId]) {
        let mut stack: Vec<Task> = nodes.iter().rev().map(|&id| Task::Node(id)).collect();
        while let Some(task) = stack.pop() {
            match task {
                Task::Node(id) => self.node(id, &mut stack),
                Task::EndMarked(mexp) => {
                    self.u8(op::END_MARKED_SUBEXPRESSION);
                    self.u16(mexp);
                }
                Task::EndLookaround { insn } => {
                    let offset = self.offset();
                    self.patch_u32(insn + 8, offset);
                }
                Task::EndWidth1Loop { insn } => {
                    let offset = self.offset();
                    self.patch_u32(insn + 14, offset);
                }
                Task::EndSimpleLoop { insn, entry } => {
                    self.u8(op::END_SIMPLE_LOOP);
                    self.u32(entry);
                    let offset = self.offset();
                    self.patch_u32(insn + 2, offset);
                }
                Task::EndLoop { insn, entry } => {
                    self.u8(op::END_LOOP);
                    self.u32(entry);
                    let offset = self.offset();
                    self.patch_u32(insn + 19, offset);
                }
                Task::AlternativeHeader {
                    state,
                    primary,
                    secondary,
                } => {
                    self.alternations[state].header = self.out.len();
                    self.u8(op::ALTERNATION);
                    self.u32(0);
                    self.u8(primary);
                    self.u8(secondary);
                }
                Task::AlternativeJump { state } => {
                    self.alternations[state].jumps.push(self.out.len());
                    self.u8(op::JUMP32);
                    self.u32(0);
                    let offset = self.offset();
                    let header = self.alternations[state].header;
                    self.patch_u32(header + 1, offset);
                }
                Task::EndAlternation { state } => {
                    let offset = self.offset();
                    for jump in std::mem::take(&mut self.alternations[state].jumps) {
                        self.patch_u32(jump + 1, offset);
                    }
                }
            }
        }
    }

    /// Emit `id`, pushing whatever must follow its children onto `stack`
    /// beneath them.
    fn node(&mut self, id: NodeId, stack: &mut Vec<Task>) {
        let push_list = |stack: &mut Vec<Task>, list: &[NodeId]| {
            stack.extend(list.iter().rev().map(|&id| Task::Node(id)));
        };
        match &self.arena.nodes[id] {
            Node::Empty => {}
            Node::Goal => self.u8(op::GOAL),
            Node::LeftAnchor { .. } => self.u8(op::LEFT_ANCHOR),
            Node::RightAnchor => self.u8(op::RIGHT_ANCHOR),
            Node::WordBoundary { invert } => {
                self.u8(op::WORD_BOUNDARY);
                self.u8(u8::from(*invert));
            }
            Node::BackRef { mexp } => {
                self.u8(op::BACK_REF);
                self.u16(*mexp);
            }
            Node::MatchAny { unicode, dot_all } => self.u8(match (unicode, dot_all) {
                (true, true) => op::U16_MATCH_ANY,
                (true, false) => op::U16_MATCH_ANY_BUT_NEWLINE,
                (false, true) => op::MATCH_ANY,
                (false, false) => op::MATCH_ANY_BUT_NEWLINE,
            }),
            Node::MatchChar {
                chars,
                icase,
                unicode,
            } => self.match_chars(chars, *icase, *unicode),
            Node::Bracket(bracket) => self.bracket(bracket),
            Node::MarkedSubexpression { contents, mexp, .. } => {
                self.u8(op::BEGIN_MARKED_SUBEXPRESSION);
                self.u16(*mexp);
                stack.push(Task::EndMarked(*mexp));
                push_list(stack, contents);
            }
            Node::Lookaround {
                exp,
                exp_constraints,
                invert,
                forwards,
                mexp_begin,
                mexp_end,
            } => {
                let insn = self.out.len();
                self.u8(op::LOOKAROUND);
                self.u8(u8::from(*invert));
                self.u8(u8::from(*forwards));
                self.u8(*exp_constraints);
                self.u16(*mexp_begin);
                self.u16(*mexp_end);
                self.u32(0);
                stack.push(Task::EndLookaround { insn });
                push_list(stack, exp);
            }
            Node::Loop {
                loop_id,
                min,
                max,
                mexp_begin,
                mexp_end,
                greedy,
                loopee,
                loopee_constraints,
            } => {
                let entry = self.offset();
                let insn = self.out.len();
                if loopee.len() == 1 && self.arena.matches_exactly_one_character(loopee[0]) {
                    self.u8(op::WIDTH1_LOOP);
                    self.u32(*loop_id);
                    self.u32(*min);
                    self.u32(*max);
                    self.u8(u8::from(*greedy));
                    self.u32(0);
                    stack.push(Task::EndWidth1Loop { insn });
                } else if *min == 0
                    && *max == u32::MAX
                    && mexp_begin == mexp_end
                    && *greedy
                    && loopee_constraints & NON_EMPTY != 0
                {
                    self.u8(op::BEGIN_SIMPLE_LOOP);
                    self.u8(*loopee_constraints);
                    self.u32(0);
                    stack.push(Task::EndSimpleLoop { insn, entry });
                } else {
                    self.u8(op::BEGIN_LOOP);
                    self.u32(*loop_id);
                    self.u32(*min);
                    self.u32(*max);
                    self.u16(*mexp_begin);
                    self.u16(*mexp_end);
                    self.u8(u8::from(*greedy));
                    self.u8(*loopee_constraints);
                    self.u32(0);
                    stack.push(Task::EndLoop { insn, entry });
                }
                push_list(stack, loopee);
            }
            Node::Alternation {
                alternatives,
                element,
                rest,
            } => {
                // [Alternation a0][a0][Jump][Alternation a1][a1][Jump]...[an]
                // Each Alternation's secondary branch is the instruction after
                // its Jump; every Jump goes to the end.
                let state = self.alternations.len();
                self.alternations.push(AlternationState::default());
                let last = alternatives.len() - 1;
                stack.push(Task::EndAlternation { state });
                push_list(stack, &alternatives[last]);
                for index in (0..last).rev() {
                    stack.push(Task::AlternativeJump { state });
                    push_list(stack, &alternatives[index]);
                    stack.push(Task::AlternativeHeader {
                        state,
                        primary: element[index],
                        secondary: rest[index + 1],
                    });
                }
            }
        }
    }

    fn match_chars(&mut self, chars: &[u32], icase: bool, unicode: bool) {
        let mut remaining = chars;
        while !remaining.is_empty() {
            let ascii = remaining.iter().take_while(|&&c| c <= 127).count();
            self.ascii_chars(&remaining[..ascii], icase);
            remaining = &remaining[ascii..];
            let other = remaining.iter().take_while(|&&c| c > 127).count();
            for &c in &remaining[..other] {
                if may_require_surrogate_pair(c, unicode) {
                    self.u8(if icase {
                        op::U16_MATCH_CHAR_ICASE32
                    } else {
                        op::U16_MATCH_CHAR32
                    });
                    self.u32(c);
                } else {
                    self.u8(if icase {
                        op::MATCH_CHAR_ICASE16
                    } else {
                        op::MATCH_CHAR16
                    });
                    self.u16(c as u16);
                }
            }
            remaining = &remaining[other..];
        }
    }

    fn ascii_chars(&mut self, chars: &[u32], icase: bool) {
        let mut remaining = chars;
        while remaining.len() >= MIN_MATCH_N_CHAR_COUNT {
            let (group, rest) = remaining.split_at(remaining.len().min(MAX_MATCH_N_CHAR_COUNT));
            self.u8(if icase {
                op::MATCH_N_CHAR_ICASE8
            } else {
                op::MATCH_N_CHAR8
            });
            self.u8(group.len() as u8);
            self.out.extend(group.iter().map(|&c| c as u8));
            remaining = rest;
        }
        for &c in remaining {
            self.u8(if icase {
                op::MATCH_CHAR_ICASE8
            } else {
                op::MATCH_CHAR8
            });
            self.u8(c as u8);
        }
    }

    fn bracket(&mut self, bracket: &Bracket) {
        let set = if bracket.icase {
            make_canonically_equivalent(&bracket.set, bracket.unicode)
        } else {
            bracket.set.clone()
        };
        let (positive, negative) = bracket.classes.iter().fold((0, 0), |(p, n), class| {
            if class.inverted {
                (p, n | class.kind)
            } else {
                (p | class.kind, n)
            }
        });
        self.u8(if bracket.unicode {
            op::U16_BRACKET
        } else {
            op::BRACKET
        });
        self.u32(set.ranges().len() as u32);
        // Bitfields: negate:1, positive classes:3, negative classes:3.
        self.u8(u8::from(bracket.negate) | positive << 1 | negative << 4);
        for range in set.ranges() {
            self.u32(range.first);
            self.u32(range.first + range.length - 1);
        }
    }
}

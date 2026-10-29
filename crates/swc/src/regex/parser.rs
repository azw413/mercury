//! Pattern parser and compile driver, ported from Hermes's `RegexParser.cpp`
//! and `Regex.h`. Like Hermes it keeps an explicit stack instead of
//! recursing, so deeply nested patterns can't overflow ours.

use std::collections::HashMap;

use crate::regex::RegexError;
use crate::regex::flags::SyntaxFlags;
use crate::regex::node::{
    ANCHORED_AT_START, Arena, CharacterClass, DIGITS, HEADER_SIZE, Node, NodeId, NodeList, SPACES,
    WORDS,
};
use crate::regex::unicode::{
    CodePointRange, add_property_ranges, canonicalize, is_high_surrogate, is_low_surrogate,
    is_unicode_id_continue, is_unicode_id_start, is_unicode_property_name,
    is_unicode_property_value, property_ranges, surrogate_pair_to_code_point,
};

const MAX_CAPTURE_GROUP_COUNT: u16 = u16::MAX;
const MAX_LOOP_COUNT: u32 = u16::MAX as u32;

type GroupName = Vec<u16>;

/// A parsed pattern, ready to compile.
pub struct Regex {
    arena: Arena,
    flags: SyntaxFlags,
    marked_count: u16,
    loop_count: u32,
    nodes: NodeList,
    match_constraints: u8,
    names: HashMap<GroupName, u32>,
    ordered_group_names: Vec<GroupName>,
    saw_named_backref_before_group: bool,
    /// Named backreferences seen before their group. Like Hermes, entries
    /// from an abandoned first parse stay here and are re-checked.
    unresolved_named_backrefs: Vec<(GroupName, NodeId)>,
}

impl Regex {
    pub fn parse(pattern: &[u16], flags: SyntaxFlags) -> Result<Self, RegexError> {
        let mut regex = Self {
            arena: Arena::default(),
            flags,
            marked_count: 0,
            loop_count: 0,
            nodes: Vec::new(),
            match_constraints: 0,
            names: HashMap::new(),
            ordered_group_names: Vec::new(),
            saw_named_backref_before_group: false,
            unresolved_named_backrefs: Vec::new(),
        };
        let mut has_named_groups = flags.unicode;
        let (mut result, max_back_ref) = regex.parse_with_back_ref_limit(
            pattern,
            u32::from(MAX_CAPTURE_GROUP_COUNT),
            has_named_groups,
        );
        if regex.loop_count > MAX_LOOP_COUNT {
            return Err(RegexError::PatternExceedsParseLimits);
        }
        // Annex B: \N is a backreference only if there are at least N groups,
        // which we only know now. Reparse with that limit, so larger escapes
        // become octal or identity escapes. Likewise \k<name> is only a named
        // reference if the pattern has named groups.
        let reparse_for_numbered = result.is_ok() && max_back_ref > u32::from(regex.marked_count);
        let mut reparse_for_named = false;
        if !flags.unicode && !regex.names.is_empty() && regex.saw_named_backref_before_group {
            reparse_for_named = true;
            has_named_groups = true;
        }
        if reparse_for_numbered || reparse_for_named {
            if flags.unicode {
                return Err(RegexError::EscapeInvalid);
            }
            let limit = u32::from(regex.marked_count);
            regex.loop_count = 0;
            regex.marked_count = 0;
            regex.match_constraints = 0;
            regex.names.clear();
            regex.ordered_group_names.clear();
            result = regex
                .parse_with_back_ref_limit(pattern, limit, has_named_groups)
                .0;
        }
        result.map(|()| regex)
    }

    fn parse_with_back_ref_limit(
        &mut self,
        pattern: &[u16],
        back_ref_limit: u32,
        has_named_groups: bool,
    ) -> (Result<(), RegexError>, u32) {
        self.nodes.clear();
        self.append(Node::Empty);
        let flags = self.flags;
        let mut parser = Parser {
            re: self,
            input: pattern,
            pos: 0,
            error: None,
            flags,
            back_ref_limit,
            max_back_ref: 0,
            has_named_groups,
        };
        parser.consume_disjunction();
        let (error, max_back_ref) = (parser.error, parser.max_back_ref);
        if let Some(error) = error {
            self.match_constraints = self.arena.constraints_for_list(&self.nodes);
            return (Err(error), max_back_ref);
        }
        self.append(Node::Goal);
        let mut nodes = std::mem::take(&mut self.nodes);
        self.arena.optimize(&mut nodes, self.flags);
        self.nodes = nodes;
        if !self.resolve_named_backrefs() {
            return (
                Err(RegexError::NonexistentNamedCaptureReference),
                max_back_ref,
            );
        }
        self.match_constraints = self.arena.constraints_for_list(&self.nodes);
        (Ok(()), max_back_ref)
    }

    fn resolve_named_backrefs(&mut self) -> bool {
        for (name, id) in &self.unresolved_named_backrefs {
            let Some(&group) = self.names.get(name) else {
                return false;
            };
            if let Node::BackRef { mexp } = self.arena.get_mut(*id) {
                *mexp = (group - 1) as u16;
            }
        }
        true
    }

    /// Named groups in definition order, with their 1-based numbers.
    pub fn group_names(&self) -> Vec<(GroupName, u32)> {
        self.ordered_group_names
            .iter()
            .map(|name| (name.clone(), self.names[name]))
            .collect()
    }

    /// The bytecode: header, then instructions.
    pub fn compile(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + 16);
        out.extend_from_slice(&self.marked_count.to_le_bytes());
        out.extend_from_slice(&(self.loop_count as u16).to_le_bytes());
        out.push(self.flags.to_byte());
        out.push(self.match_constraints);
        self.arena.emit(&self.nodes, &mut out);
        out
    }

    fn append(&mut self, node: Node) -> NodeId {
        let id = self.arena.push(node);
        self.nodes.push(id);
        id
    }

    fn current_node(&self) -> NodeId {
        *self
            .nodes
            .last()
            .expect("node list always starts with an empty node")
    }

    /// Remove and return every node after `splice_point`.
    fn splice_out(&mut self, splice_point: NodeId) -> NodeList {
        let index = self
            .nodes
            .iter()
            .rposition(|&id| id == splice_point)
            .expect("splice point is in the node list");
        self.nodes.split_off(index + 1)
    }

    fn push_char(&mut self, c: u32) {
        let c = if self.flags.ignore_case {
            canonicalize(c, self.flags.unicode)
        } else {
            c
        };
        self.append(Node::MatchChar {
            chars: vec![c],
            icase: self.flags.ignore_case,
            unicode: self.flags.unicode,
        });
    }

    fn start_bracket(&mut self, negate: bool) -> NodeId {
        self.append(Node::new_bracket(negate, self.flags))
    }

    fn push_char_class(&mut self, class: CharacterClass) {
        let bracket = self.start_bracket(false);
        self.arena.bracket_mut(bracket).classes.push(class);
    }

    fn push_loop(&mut self, quantifier: &Quantifier, loopee: NodeList) {
        let loopee_constraints = self.arena.constraints_for_list(&loopee);
        let loop_id = self.loop_count;
        self.loop_count += 1;
        self.append(Node::Loop {
            loop_id,
            min: quantifier.min,
            max: quantifier.max,
            mexp_begin: quantifier.start_marked,
            mexp_end: self.marked_count,
            greedy: quantifier.greedy,
            loopee,
            loopee_constraints,
        });
    }

    fn push_back_ref(&mut self, mexp: u32) {
        self.append(Node::BackRef { mexp: mexp as u16 });
    }

    fn push_named_back_ref(&mut self, name: GroupName) {
        match self.names.get(&name) {
            Some(&group) => self.push_back_ref(group - 1),
            None => {
                // The group may be defined later; check once parsing ends.
                let id = self.append(Node::BackRef { mexp: 0 });
                self.unresolved_named_backrefs.push((name, id));
            }
        }
    }

    fn push_alternation(&mut self, alternatives: Vec<NodeList>) {
        let element: Vec<u8> = alternatives
            .iter()
            .map(|alternative| self.arena.constraints_for_list(alternative))
            .collect();
        let mut rest = element.clone();
        for index in (0..rest.len() - 1).rev() {
            rest[index] &= rest[index + 1];
        }
        self.append(Node::Alternation {
            alternatives,
            element,
            rest,
        });
    }

    fn push_marked_subexpression(&mut self, contents: NodeList, mexp: u16) {
        let contents_constraints = self.arena.constraints_for_list(&contents);
        self.append(Node::MarkedSubexpression {
            contents,
            contents_constraints,
            mexp,
        });
    }

    fn push_lookaround(
        &mut self,
        mut exp: NodeList,
        mexp_begin: u16,
        mexp_end: u16,
        invert: bool,
        forwards: bool,
    ) {
        if !forwards {
            self.arena.reverse_list(&mut exp);
        }
        exp.push(self.arena.push(Node::Goal));
        let mut exp_constraints = self.arena.constraints_for_list(&exp);
        // /(?<=^abc)def/ matches "def" in "abcdef", which isn't at the start.
        if !forwards {
            exp_constraints &= !ANCHORED_AT_START;
        }
        self.append(Node::Lookaround {
            exp,
            exp_constraints,
            invert,
            forwards,
            mexp_begin,
            mexp_end,
        });
    }

    /// Record a named group; false if the name is already taken.
    fn add_named_capture_group(&mut self, name: GroupName, mexp: u16) -> bool {
        self.ordered_group_names.push(name.clone());
        match self.names.entry(name) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(u32::from(mexp) + 1);
                true
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Quantifier {
    min: u32,
    max: u32,
    greedy: bool,
    /// The first group inside the quantified term.
    start_marked: u16,
    /// The node before the quantified term; the term is everything after it.
    node_start: NodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    Alternation,
    CapturingGroup,
    NamedCapturingGroup,
    NonCapturingGroup,
    Lookaround { negate: bool, forwards: bool },
}

struct StackElement {
    frame: Frame,
    /// For alternations, later nodes are the current alternative; for groups,
    /// later nodes are the group's contents.
    splice_point: NodeId,
    /// The group's index, or for lookarounds the group count on entry.
    mexp: u16,
    quantifier: Option<Quantifier>,
    alternatives: Vec<NodeList>,
}

/// One bracket member: a code point, a class escape, or a property escape.
enum ClassAtom {
    CodePoint(u32),
    Class(CharacterClass),
    Property(&'static [(u16, u16)], bool),
}

struct Parser<'a> {
    re: &'a mut Regex,
    input: &'a [u16],
    pos: usize,
    error: Option<RegexError>,
    flags: SyntaxFlags,
    back_ref_limit: u32,
    max_back_ref: u32,
    has_named_groups: bool,
}

fn is_ascii_unit(unit: u16, range: std::ops::RangeInclusive<u8>) -> bool {
    u8::try_from(unit).is_ok_and(|byte| range.contains(&byte))
}

impl Parser<'_> {
    /// Record the first error and skip to the end, which ends every loop.
    fn set_error(&mut self, error: RegexError) {
        if self.error.is_none() {
            self.error = Some(error);
            self.pos = self.input.len();
        }
    }

    fn at_end(&self) -> bool {
        self.pos == self.input.len()
    }

    fn peek(&self) -> Option<u16> {
        self.input.get(self.pos).copied()
    }

    fn check(&self, c: u8) -> bool {
        self.peek() == Some(u16::from(c))
    }

    fn try_consume(&mut self, c: u8) -> bool {
        let found = self.check(c);
        self.pos += usize::from(found);
        found
    }

    fn try_consume_str(&mut self, sequence: &str) -> bool {
        let units = sequence.as_bytes();
        let matches = self.input[self.pos..].len() >= units.len()
            && self.input[self.pos..]
                .iter()
                .zip(units)
                .all(|(&unit, &byte)| unit == u16::from(byte));
        if matches {
            self.pos += units.len();
        }
        matches
    }

    fn consume_if(&mut self, predicate: impl Fn(u16) -> bool) -> Option<u16> {
        let unit = self.peek().filter(|&unit| predicate(unit))?;
        self.pos += 1;
        Some(unit)
    }

    fn prepare_quantifier(&self) -> Quantifier {
        Quantifier {
            min: 0,
            max: u32::MAX,
            greedy: true,
            start_marked: self.re.marked_count,
            node_start: self.re.current_node(),
        }
    }

    fn apply_quantifier(&mut self, quantifier: &Quantifier) {
        if quantifier.min > quantifier.max {
            self.set_error(RegexError::BraceRange);
            return;
        }
        let quantified = self.re.splice_out(quantifier.node_start);
        self.re.push_loop(quantifier, quantified);
    }

    fn element(&self, frame: Frame) -> StackElement {
        StackElement {
            frame,
            splice_point: self.re.current_node(),
            mexp: 0,
            quantifier: None,
            alternatives: Vec::new(),
        }
    }

    fn open_alternation(&mut self, stack: &mut Vec<StackElement>) {
        stack.push(self.element(Frame::Alternation));
    }

    fn close_alternation(&mut self, stack: &mut Vec<StackElement>) {
        if stack
            .last()
            .is_some_and(|top| top.frame == Frame::Alternation)
        {
            let mut top = stack.pop().unwrap();
            let last = self.re.splice_out(top.splice_point);
            top.alternatives.push(last);
            self.re.push_alternation(top.alternatives);
        }
    }

    fn open_group(&mut self, stack: &mut Vec<StackElement>, frame: Frame) {
        // Prepare the quantifier before counting this group, which is the
        // first group it quantifies.
        let quantifier = self.prepare_quantifier();
        let mut element = self.element(frame);
        element.quantifier = Some(quantifier);
        match frame {
            Frame::CapturingGroup | Frame::NamedCapturingGroup => {
                if self.re.marked_count == MAX_CAPTURE_GROUP_COUNT {
                    self.set_error(RegexError::PatternExceedsParseLimits);
                    return;
                }
                element.mexp = self.re.marked_count;
                self.re.marked_count += 1;
            }
            Frame::Lookaround { .. } => element.mexp = self.re.marked_count,
            Frame::NonCapturingGroup | Frame::Alternation => {}
        }
        if frame == Frame::NamedCapturingGroup {
            let mut name = GroupName::new();
            if !self.try_consume_group_name(&mut name) {
                self.set_error(RegexError::InvalidCaptureGroupName);
                return;
            }
            if !self.re.add_named_capture_group(name, element.mexp) {
                self.set_error(RegexError::DuplicateCaptureGroupName);
                return;
            }
            self.has_named_groups = true;
        }
        stack.push(element);
    }

    fn close_group(&mut self, stack: &mut Vec<StackElement>) {
        let element = stack.pop().expect("group stack is not empty");
        let mut quantifier_allowed = true;
        match element.frame {
            Frame::Alternation => unreachable!("alternations close in close_alternation"),
            Frame::CapturingGroup | Frame::NamedCapturingGroup => {
                let contents = self.re.splice_out(element.splice_point);
                self.re.push_marked_subexpression(contents, element.mexp);
            }
            Frame::NonCapturingGroup => {}
            Frame::Lookaround { negate, forwards } => {
                // Annex B allows quantified lookaheads, but not under /u.
                quantifier_allowed = !self.flags.unicode && forwards;
                let exp = self.re.splice_out(element.splice_point);
                let mexp_end = self.re.marked_count;
                self.re
                    .push_lookaround(exp, element.mexp, mexp_end, negate, forwards);
            }
        }
        let mut quantifier = element.quantifier.expect("groups have a quantifier");
        if self.try_consume_quantifier(&mut quantifier) {
            if !quantifier_allowed {
                self.set_error(RegexError::InvalidRepeat);
                return;
            }
            self.apply_quantifier(&quantifier);
        }
    }

    fn consume_disjunction(&mut self) {
        let first_node = self.re.current_node();
        let mut stack: Vec<StackElement> = Vec::new();
        while let Some(c) = self.peek() {
            match u8::try_from(c) {
                Ok(b'|') => {
                    self.pos += 1;
                    let splice_point = stack.last().map_or(first_node, |top| top.splice_point);
                    let nodes = self.re.splice_out(splice_point);
                    if stack
                        .last()
                        .is_none_or(|top| top.frame != Frame::Alternation)
                    {
                        self.open_alternation(&mut stack);
                    }
                    stack.last_mut().unwrap().alternatives.push(nodes);
                }
                Ok(b'(') => {
                    let frame = if self.try_consume_str("(?=") {
                        Frame::Lookaround {
                            negate: false,
                            forwards: true,
                        }
                    } else if self.try_consume_str("(?!") {
                        Frame::Lookaround {
                            negate: true,
                            forwards: true,
                        }
                    } else if self.try_consume_str("(?<=") {
                        Frame::Lookaround {
                            negate: false,
                            forwards: false,
                        }
                    } else if self.try_consume_str("(?<!") {
                        Frame::Lookaround {
                            negate: true,
                            forwards: false,
                        }
                    } else if self.try_consume_str("(?<") {
                        Frame::NamedCapturingGroup
                    } else if self.try_consume_str("(?:") {
                        Frame::NonCapturingGroup
                    } else {
                        self.pos += 1;
                        Frame::CapturingGroup
                    };
                    self.open_group(&mut stack, frame);
                }
                Ok(b')') => {
                    self.pos += 1;
                    self.close_alternation(&mut stack);
                    if stack.is_empty() {
                        self.set_error(RegexError::UnbalancedParenthesis);
                        return;
                    }
                    self.close_group(&mut stack);
                }
                _ => {}
            }
            self.consume_term();
        }
        self.close_alternation(&mut stack);
        if !stack.is_empty() {
            self.set_error(RegexError::UnbalancedParenthesis);
        }
    }

    fn consume_term(&mut self) {
        while let Some(c) = self.peek() {
            let mut quantifier = self.prepare_quantifier();
            let mut quantifier_allowed = true;
            match u8::try_from(c).unwrap_or(0x80) {
                b'^' => {
                    self.re.append(Node::LeftAnchor {
                        multiline: self.flags.multiline,
                    });
                    self.pos += 1;
                    quantifier_allowed = false;
                }
                b'$' => {
                    self.re.append(Node::RightAnchor);
                    self.pos += 1;
                    quantifier_allowed = false;
                }
                b'\\' => {
                    self.pos += 1;
                    match self.peek() {
                        None => {
                            self.set_error(RegexError::EscapeIncomplete);
                            return;
                        }
                        Some(next) if next == u16::from(b'b') || next == u16::from(b'B') => {
                            self.re.append(Node::WordBoundary {
                                invert: next == u16::from(b'B'),
                            });
                            self.pos += 1;
                            quantifier_allowed = false;
                        }
                        Some(_) => self.consume_atom_escape(),
                    }
                }
                b'.' => {
                    self.pos += 1;
                    self.re.append(Node::MatchAny {
                        unicode: self.flags.unicode,
                        dot_all: self.flags.dot_all,
                    });
                }
                b'[' => self.consume_character_class(),
                b'*' | b'+' | b'?' => {
                    self.set_error(RegexError::InvalidRepeat);
                    return;
                }
                b'{' => {
                    // A valid quantifier with nothing before it is an error;
                    // otherwise Annex B makes a lone { a literal, except under /u.
                    let mut ignored = quantifier;
                    if self.try_consume_quantifier(&mut ignored) {
                        self.set_error(RegexError::InvalidRepeat);
                        return;
                    } else if self.flags.unicode {
                        self.set_error(RegexError::InvalidQuantifierBracket);
                        return;
                    }
                    self.re.push_char(u32::from(b'{'));
                    self.pos += 1;
                }
                b'|' | b'(' | b')' => return,
                b'}' | b']' if self.flags.unicode => {
                    self.set_error(if c == u16::from(b'}') {
                        RegexError::InvalidQuantifierBracket
                    } else {
                        RegexError::UnbalancedBracket
                    });
                    return;
                }
                _ => {
                    if let Some(cp) = self.try_consume_surrogate_pair() {
                        self.re.push_char(cp);
                    } else {
                        self.pos += 1;
                        self.re.push_char(u32::from(c));
                    }
                }
            }
            if self.try_consume_quantifier(&mut quantifier) {
                if !quantifier_allowed {
                    self.set_error(RegexError::InvalidRepeat);
                    return;
                }
                self.apply_quantifier(&quantifier);
            }
        }
    }

    /// Under /u, consume a surrogate pair as one code point.
    fn try_consume_surrogate_pair(&mut self) -> Option<u32> {
        if !self.flags.unicode {
            return None;
        }
        let saved = self.pos;
        let high = self.consume_if(|unit| is_high_surrogate(u32::from(unit)));
        let low = self.consume_if(|unit| is_low_surrogate(u32::from(unit)));
        if let (Some(high), Some(low)) = (high, low) {
            return Some(surrogate_pair_to_code_point(
                u32::from(high),
                u32::from(low),
            ));
        }
        self.pos = saved;
        None
    }

    fn try_consume_and_append_surrogate_pair(
        &mut self,
        name: &mut GroupName,
        predicate: fn(u32) -> bool,
    ) -> bool {
        let saved = self.pos;
        let high = self.consume_if(|unit| is_high_surrogate(u32::from(unit)));
        let low = self.consume_if(|unit| is_low_surrogate(u32::from(unit)));
        if let (Some(high), Some(low)) = (high, low)
            && predicate(surrogate_pair_to_code_point(
                u32::from(high),
                u32::from(low),
            ))
        {
            name.push(high);
            name.push(low);
            return true;
        }
        self.pos = saved;
        false
    }

    fn try_consume_group_name(&mut self, name: &mut GroupName) -> bool {
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return false;
            };
            if c == u16::from(b'>') {
                if name.is_empty() {
                    return false;
                }
                self.pos += 1;
                return true;
            }
            let predicate = if first {
                is_unicode_id_start
            } else {
                is_unicode_id_continue
            };
            if !self.try_consume_identifier_part(name, predicate) {
                return false;
            }
            first = false;
        }
    }

    fn try_consume_identifier_part(
        &mut self,
        name: &mut GroupName,
        predicate: fn(u32) -> bool,
    ) -> bool {
        let c = self.peek().expect("caller checked for input");
        if predicate(u32::from(c)) {
            self.pos += 1;
            name.push(c);
            return true;
        }
        // As in Hermes, a backslash not followed by `u` stays consumed.
        if self.try_consume(b'\\')
            && self.check(b'u')
            && let Some(cp) = self.try_consume_unicode_escape(true)
        {
            if !predicate(cp) {
                return false;
            }
            write_code_point_utf16(cp, name);
            return true;
        }
        self.try_consume_and_append_surrogate_pair(name, predicate)
    }

    fn try_consume_quantifier(&mut self, quantifier: &mut Quantifier) -> bool {
        if !self.try_consume_quantifier_prefix(quantifier) {
            return false;
        }
        quantifier.greedy = !self.try_consume(b'?');
        true
    }

    fn try_consume_quantifier_prefix(&mut self, quantifier: &mut Quantifier) -> bool {
        let Some(c) = self.peek() else {
            return false;
        };
        match u8::try_from(c).unwrap_or(0) {
            b'*' => {
                self.pos += 1;
                (quantifier.min, quantifier.max) = (0, u32::MAX);
                true
            }
            b'+' => {
                self.pos += 1;
                (quantifier.min, quantifier.max) = (1, u32::MAX);
                true
            }
            b'?' => {
                self.pos += 1;
                (quantifier.min, quantifier.max) = (0, 1);
                true
            }
            b'{' => {
                let saved = self.pos;
                self.pos += 1;
                if let Some(min) = self.try_consume_decimal() {
                    quantifier.min = min;
                    quantifier.max = if self.try_consume(b',') {
                        self.try_consume_decimal().unwrap_or(u32::MAX)
                    } else {
                        min
                    };
                    if self.try_consume(b'}') {
                        return true;
                    }
                }
                self.pos = saved;
                false
            }
            _ => false,
        }
    }

    fn consume_character_class(&mut self) {
        self.pos += 1;
        let unicode = self.flags.unicode;
        let negate = self.try_consume(b'^');
        let bracket = self.re.start_bracket(negate);
        loop {
            if self.at_end() {
                self.set_error(RegexError::UnbalancedBracket);
                return;
            }
            if self.try_consume(b']') {
                return;
            }
            let Some(first) = self.try_consume_class_atom() else {
                continue;
            };
            if !self.try_consume(b'-') {
                self.add_class_atom(bracket, &first);
                continue;
            }
            let Some(second) = self.try_consume_class_atom() else {
                // [a-] is a and -.
                self.add_class_atom(bracket, &first);
                self.add_class_atom(bracket, &ClassAtom::CodePoint(u32::from(b'-')));
                continue;
            };
            match (&first, &second) {
                (ClassAtom::CodePoint(low), ClassAtom::CodePoint(high)) => {
                    if low > high {
                        self.set_error(RegexError::CharacterRange);
                        return;
                    }
                    let length = high - low + 1;
                    self.re
                        .arena
                        .bracket_mut(bracket)
                        .set
                        .add_range(CodePointRange {
                            first: *low,
                            length,
                        });
                }
                _ if unicode => {
                    // [\d-z] and [\p{Number}-z] are errors under /u...
                    self.set_error(RegexError::CharacterRange);
                    return;
                }
                _ => {
                    // ...but otherwise mean \d, - and z.
                    self.add_class_atom(bracket, &first);
                    self.add_class_atom(bracket, &ClassAtom::CodePoint(u32::from(b'-')));
                    self.add_class_atom(bracket, &second);
                }
            }
        }
    }

    fn add_class_atom(&mut self, bracket: NodeId, atom: &ClassAtom) {
        let bracket = self.re.arena.bracket_mut(bracket);
        match *atom {
            ClassAtom::CodePoint(cp) => bracket.set.add(cp),
            ClassAtom::Class(class) => bracket.classes.push(class),
            ClassAtom::Property(pools, inverted) => {
                add_property_ranges(&mut bracket.set, pools, inverted)
            }
        }
    }

    fn class_escape(c: u16) -> Option<CharacterClass> {
        let (kind, inverted) = match u8::try_from(c).ok()? {
            b'd' => (DIGITS, false),
            b'D' => (DIGITS, true),
            b's' => (SPACES, false),
            b'S' => (SPACES, true),
            b'w' => (WORDS, false),
            b'W' => (WORDS, true),
            _ => return None,
        };
        Some(CharacterClass { kind, inverted })
    }

    fn try_consume_class_atom(&mut self) -> Option<ClassAtom> {
        let c = self.peek()?;
        if c == u16::from(b']') {
            return None;
        }
        if c != u16::from(b'\\') {
            if let Some(cp) = self.try_consume_surrogate_pair() {
                return Some(ClassAtom::CodePoint(cp));
            }
            self.pos += 1;
            return Some(ClassAtom::CodePoint(u32::from(c)));
        }
        self.pos += 1;
        let Some(escaped) = self.peek() else {
            self.set_error(RegexError::EscapeIncomplete);
            return None;
        };
        if let Some(class) = Self::class_escape(escaped) {
            self.pos += 1;
            return Some(ClassAtom::Class(class));
        }
        if (escaped == u16::from(b'p') || escaped == u16::from(b'P')) && self.flags.unicode {
            self.pos += 1;
            let pools = self.consume_property_escape()?;
            return Some(ClassAtom::Property(pools, escaped == u16::from(b'P')));
        }
        if escaped == u16::from(b'b') {
            self.pos += 1;
            return Some(ClassAtom::CodePoint(0x08));
        }
        if escaped == u16::from(b'-') && self.flags.unicode {
            self.pos += 1;
            return Some(ClassAtom::CodePoint(u32::from(b'-')));
        }
        Some(ClassAtom::CodePoint(self.consume_character_escape()))
    }

    /// After `\p` or `\P` under /u: parse `{...}` and look the property up.
    fn consume_property_escape(&mut self) -> Option<&'static [(u16, u16)]> {
        let mut name = Vec::new();
        let mut value = Vec::new();
        if !self.try_consume(b'{') || !self.try_consume_property_expression(&mut name, &mut value) {
            self.set_error(RegexError::InvalidPropertyName);
            return None;
        }
        // Hermes collects these as bytes, truncating non-ASCII digits, which
        // then match nothing.
        let pools = std::str::from_utf8(&name)
            .ok()
            .zip(std::str::from_utf8(&value).ok())
            .and_then(|(name, value)| property_ranges(name, value))
            .filter(|pools| !pools.is_empty());
        if pools.is_none() {
            self.set_error(RegexError::InvalidPropertyName);
        }
        pools
    }

    fn try_consume_property_expression(&mut self, name: &mut Vec<u8>, value: &mut Vec<u8>) -> bool {
        let parsed = !self.at_end() && {
            while let Some(unit) = self.consume_if(|unit| is_unicode_property_name(u32::from(unit)))
            {
                name.push(unit as u8);
            }
            if self.try_consume(b'=') {
                while let Some(unit) =
                    self.consume_if(|unit| is_unicode_property_value(u32::from(unit)))
                {
                    value.push(unit as u8);
                }
                !value.is_empty()
            } else {
                true
            }
        };
        if !parsed || !self.try_consume(b'}') {
            self.set_error(RegexError::InvalidPropertyName);
            return false;
        }
        true
    }

    /// Annex B LegacyOctalEscapeSequence; an error under /u.
    fn consume_legacy_octal(&mut self) -> u32 {
        if self.flags.unicode {
            self.set_error(RegexError::EscapeInvalid);
            return 0;
        }
        let is_octal = |unit: u16| is_ascii_unit(unit, b'0'..=b'7');
        let d1 = u32::from(self.input[self.pos]) - u32::from(b'0');
        self.pos += 1;
        let d2 = self.consume_if(is_octal);
        let d3 = if d1 <= 3 {
            self.consume_if(is_octal)
        } else {
            None
        };
        let mut result = d1;
        for digit in [d2, d3].into_iter().flatten() {
            result = result * 8 + (u32::from(digit) - u32::from(b'0'));
        }
        result
    }

    /// Decimal digits, saturating at u32::MAX; all digits are consumed.
    fn try_consume_decimal(&mut self) -> Option<u32> {
        let is_digit = |unit: u16| is_ascii_unit(unit, b'0'..=b'9');
        self.peek().filter(|&unit| is_digit(unit))?;
        let mut value: u64 = 0;
        while let Some(digit) = self.consume_if(is_digit) {
            value = (value * 10 + u64::from(digit - u16::from(b'0'))).min(u64::from(u32::MAX));
        }
        Some(value as u32)
    }

    /// Exactly `count` hex digits, or nothing consumed.
    fn try_consume_hex(&mut self, count: usize) -> Option<u32> {
        let saved = self.pos;
        let mut value = 0;
        for _ in 0..count {
            let Some(digit) = self
                .peek()
                .and_then(|unit| char::from_u32(u32::from(unit))?.to_digit(16))
            else {
                self.pos = saved;
                return None;
            };
            self.pos += 1;
            value = value * 16 + digit;
        }
        Some(value)
    }

    /// CharacterEscape, after the backslash. Never fails: IdentityEscape is
    /// the fallback (/\q/ is /q/), except where /u makes it an error.
    fn consume_character_escape(&mut self) -> u32 {
        let Some(c) = self.peek() else {
            self.set_error(RegexError::EscapeIncomplete);
            return 0;
        };
        match u8::try_from(c).unwrap_or(0x80) {
            b'f' => {
                self.pos += 1;
                0x0C
            }
            b'n' => {
                self.pos += 1;
                0x0A
            }
            b'r' => {
                self.pos += 1;
                0x0D
            }
            b't' => {
                self.pos += 1;
                0x09
            }
            b'v' => {
                self.pos += 1;
                0x0B
            }
            b'c' => {
                self.pos += 1;
                match self
                    .consume_if(|unit| u8::try_from(unit).is_ok_and(|b| b.is_ascii_alphabetic()))
                {
                    Some(letter) => u32::from(letter) % 32,
                    None => self.identity_escape(u16::from(b'c')),
                }
            }
            b'0' => {
                // \0 not followed by a digit is NUL; otherwise legacy octal.
                if self
                    .input
                    .get(self.pos + 1)
                    .is_some_and(|&unit| is_ascii_unit(unit, b'0'..=b'9'))
                {
                    self.consume_legacy_octal()
                } else {
                    self.pos += 1;
                    0
                }
            }
            b'1'..=b'7' => self.consume_legacy_octal(),
            b'u' => match self.try_consume_unicode_escape(false) {
                Some(cp) => cp,
                None => {
                    self.pos += 1;
                    self.identity_escape(c)
                }
            },
            b'x' => {
                self.pos += 1;
                // /\x1Z/ is "x1Z".
                self.try_consume_hex(2)
                    .unwrap_or_else(|| self.identity_escape(c))
            }
            _ => {
                self.pos += 1;
                self.identity_escape(c)
            }
        }
    }

    /// Under /u only syntax characters and / may be escaped.
    fn identity_escape(&mut self, c: u16) -> u32 {
        if self.flags.unicode
            && !u8::try_from(c).is_ok_and(|byte| b"^$\\.*+?()[]{}|/".contains(&byte))
        {
            self.set_error(RegexError::EscapeInvalid);
        }
        u32::from(c)
    }

    /// RegExpUnicodeEscapeSequence at `u`. Without /u (and no override) only
    /// \uXXXX is accepted, returning `None` if absent; with it, every form is
    /// accepted or an error.
    fn try_consume_unicode_escape(&mut self, override_unicode: bool) -> Option<u32> {
        let saved = self.pos;
        self.pos += 1;
        if !override_unicode && !self.flags.unicode {
            let value = self.try_consume_hex(4);
            if value.is_none() {
                self.pos = saved;
            }
            return value;
        }
        if self.try_consume(b'{') {
            let mut value = 0u32;
            let mut digits = 0;
            while let Some(digit) = self.try_consume_hex(1) {
                digits += 1;
                value = value * 16 + digit;
                if value > 0x10FFFF {
                    self.set_error(RegexError::EscapeOverflow);
                    return Some(0);
                }
            }
            if !self.try_consume(b'}') || digits == 0 {
                self.set_error(RegexError::EscapeInvalid);
                return Some(0);
            }
            return Some(value);
        }
        if let Some(high) = self.try_consume_hex(4) {
            if is_high_surrogate(high) {
                let saved = self.pos;
                if self.try_consume_str("\\u")
                    && let Some(low) = self.try_consume_hex(4)
                    && is_low_surrogate(low)
                {
                    return Some(surrogate_pair_to_code_point(high, low));
                }
                self.pos = saved;
            }
            return Some(high);
        }
        self.set_error(RegexError::EscapeInvalid);
        Some(0)
    }

    /// AtomEscape, after the backslash.
    fn consume_atom_escape(&mut self) {
        let Some(c) = self.peek() else {
            self.set_error(RegexError::EscapeIncomplete);
            return;
        };
        if let Some(class) = Self::class_escape(c) {
            self.pos += 1;
            self.re.push_char_class(class);
            return;
        }
        match u8::try_from(c).unwrap_or(0x80) {
            b'p' | b'P' if self.flags.unicode => {
                self.pos += 1;
                // \P is a negated bracket of the property's ranges.
                if let Some(pools) = self.consume_property_escape() {
                    let bracket = self.re.start_bracket(c == u16::from(b'P'));
                    let set = &mut self.re.arena.bracket_mut(bracket).set;
                    add_property_ranges(set, pools, false);
                }
            }
            b'1'..=b'9' => {
                // Under /u always a backreference; otherwise one only up to the
                // group count, then octal if it can be, else an identity escape.
                let saved = self.pos;
                let decimal = self.try_consume_decimal().expect("at a digit");
                if self.flags.unicode || decimal <= self.back_ref_limit {
                    self.max_back_ref = self.max_back_ref.max(decimal);
                    self.re.push_back_ref(decimal.wrapping_sub(1));
                } else if c < u16::from(b'8') {
                    self.pos = saved;
                    let cp = self.consume_legacy_octal();
                    self.re.push_char(cp);
                } else {
                    self.pos = saved + 1;
                    let cp = self.identity_escape(c);
                    self.re.push_char(cp);
                }
            }
            b'k' if self.flags.unicode || self.has_named_groups => {
                self.pos += 1;
                let mut name = GroupName::new();
                if !self.try_consume(b'<') || !self.try_consume_group_name(&mut name) {
                    self.set_error(RegexError::InvalidNamedReference);
                    return;
                }
                self.re.push_named_back_ref(name);
            }
            other => {
                if other == b'k' {
                    // Maybe a named reference to a group not yet seen; the
                    // caller reparses if any named group turns up.
                    self.re.saw_named_backref_before_group = true;
                }
                let cp = self.consume_character_escape();
                self.re.push_char(cp);
            }
        }
    }
}

/// Append `cp` as UTF-16. Like Hermes, this writes U+10000 as one (truncated)
/// unit; only group names are written this way, so it only affects matching
/// names against each other.
fn write_code_point_utf16(cp: u32, out: &mut GroupName) {
    if cp <= 0x10000 {
        out.push(cp as u16);
    } else {
        out.push((((cp - 0x10000) >> 10) & 0x3FF) as u16 + 0xD800);
        out.push(((cp - 0x10000) & 0x3FF) as u16 + 0xDC00);
    }
}

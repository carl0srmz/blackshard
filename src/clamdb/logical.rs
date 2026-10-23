//! The logical expression of a ClamAV `.ldb` signature: `0&1&(2|3)`, `0>5`, `(0|1|2)>3,2`.
//!
//! Each number names a sub-signature; the expression says which of them must have matched, and
//! how many times. `&` and `|` are never mixed without parentheses: ClamAV's reading of that is
//! not worth guessing at, so such an expression is not understood and its signature is skipped.

const MAX_EXPRESSION_BYTES: usize = 512;
const MAX_SUBSIGNATURES: usize = 64;
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    Greater,
    Less,
    Equal,
}

impl Compare {
    fn holds(self, value: u32, limit: u32) -> bool {
        match self {
            Self::Greater => value > limit,
            Self::Less => value < limit,
            Self::Equal => value == limit,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// The sub-signature matched at least once.
    Seen(usize),
    /// The sub-signature matched a number of times that compares so against the limit.
    Count {
        sub: usize,
        compare: Compare,
        limit: u32,
    },
    All(Vec<Expr>),
    Any(Vec<Expr>),
    /// The matches of all of `subs` added together, and optionally how many of them matched at
    /// all, compared against limits.
    Total {
        subs: Vec<usize>,
        compare: Compare,
        limit: u32,
        distinct: Option<u32>,
    },
}

impl Expr {
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || text.len() > MAX_EXPRESSION_BYTES {
            return None;
        }
        let mut parser = Parser {
            bytes: text.as_bytes(),
            at: 0,
        };
        let expression = parser.expression(0)?;
        (parser.at == parser.bytes.len()).then_some(expression)
    }

    /// Every sub-signature the expression refers to.
    pub fn subsignatures(&self, into: &mut Vec<usize>) {
        match self {
            Self::Seen(sub) | Self::Count { sub, .. } => into.push(*sub),
            Self::All(items) | Self::Any(items) => {
                for item in items {
                    item.subsignatures(into);
                }
            }
            Self::Total { subs, .. } => into.extend(subs),
        }
    }

    /// Whether `counts` (how often each sub-signature matched) satisfies the expression.
    pub fn holds(&self, counts: &[u32]) -> bool {
        let count = |sub: usize| counts.get(sub).copied().unwrap_or(0);
        match self {
            Self::Seen(sub) => count(*sub) > 0,
            Self::Count {
                sub,
                compare,
                limit,
            } => compare.holds(count(*sub), *limit),
            Self::All(items) => items.iter().all(|item| item.holds(counts)),
            Self::Any(items) => items.iter().any(|item| item.holds(counts)),
            Self::Total {
                subs,
                compare,
                limit,
                distinct,
            } => {
                let total = subs
                    .iter()
                    .fold(0u32, |sum, sub| sum.saturating_add(count(*sub)));
                let matched = subs.iter().filter(|sub| count(**sub) > 0).count() as u32;
                compare.holds(total, *limit) && distinct.is_none_or(|least| matched >= least)
            }
        }
    }

    /// How many fixed bytes a file must contain for this to hold, given `fixed[sub]` for each
    /// sub-signature: the weakest way of satisfying it. Anything that holds without a match, or
    /// that asks for few, counts for nothing.
    pub fn required_bytes(&self, fixed: &[usize]) -> usize {
        let of = |sub: usize| fixed.get(sub).copied().unwrap_or(0);
        match self {
            Self::Seen(sub) => of(*sub),
            Self::Count {
                sub,
                compare,
                limit,
            } => match compare {
                Compare::Greater => of(*sub),
                Compare::Equal if *limit > 0 => of(*sub),
                _ => 0,
            },
            Self::All(items) => items.iter().map(|item| item.required_bytes(fixed)).sum(),
            Self::Any(items) => items
                .iter()
                .map(|item| item.required_bytes(fixed))
                .min()
                .unwrap_or(0),
            Self::Total {
                subs,
                compare: Compare::Greater,
                ..
            } => subs.iter().map(|sub| of(*sub)).min().unwrap_or(0),
            Self::Total { .. } => 0,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn number(&mut self) -> Option<u32> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == start || self.at - start > 9 {
            return None;
        }
        std::str::from_utf8(&self.bytes[start..self.at])
            .ok()?
            .parse()
            .ok()
    }

    /// Atoms joined by `&` or by `|`, but not both.
    fn expression(&mut self, depth: usize) -> Option<Expr> {
        if depth > MAX_DEPTH {
            return None;
        }
        let mut items = vec![self.atom(depth)?];
        let mut joiner: Option<u8> = None;
        while let Some(byte @ (b'&' | b'|')) = self.peek() {
            if joiner.is_some_and(|seen| seen != byte) {
                return None;
            }
            joiner = Some(byte);
            self.at += 1;
            items.push(self.atom(depth)?);
        }
        Some(match joiner {
            None => items.pop()?,
            Some(b'&') => Expr::All(items),
            Some(_) => Expr::Any(items),
        })
    }

    fn atom(&mut self, depth: usize) -> Option<Expr> {
        if self.peek() == Some(b'(') {
            self.at += 1;
            let inner = self.expression(depth + 1)?;
            if self.peek() != Some(b')') {
                return None;
            }
            self.at += 1;
            return match self.comparison()? {
                None => Some(inner),
                Some((compare, limit, distinct)) => {
                    let mut subs = Vec::new();
                    inner.subsignatures(&mut subs);
                    subs.sort_unstable();
                    subs.dedup();
                    Some(Expr::Total {
                        subs,
                        compare,
                        limit,
                        distinct,
                    })
                }
            };
        }
        let sub = self.number()? as usize;
        if sub >= MAX_SUBSIGNATURES {
            return None;
        }
        match self.comparison()? {
            None => Some(Expr::Seen(sub)),
            // A single sub-signature has no "different ones" to count.
            Some((_, _, Some(_))) => None,
            Some((compare, limit, None)) => Some(Expr::Count {
                sub,
                compare,
                limit,
            }),
        }
    }

    /// An optional `>n`, `<n` or `=n`, with `,m` after it for a group. `None` is a malformed
    /// comparison; `Some(None)` is no comparison at all.
    #[allow(clippy::type_complexity)]
    fn comparison(&mut self) -> Option<Option<(Compare, u32, Option<u32>)>> {
        let compare = match self.peek() {
            Some(b'>') => Compare::Greater,
            Some(b'<') => Compare::Less,
            Some(b'=') => Compare::Equal,
            _ => return Some(None),
        };
        self.at += 1;
        let limit = self.number()?;
        let distinct = if self.peek() == Some(b',') {
            self.at += 1;
            Some(self.number()?)
        } else {
            None
        };
        Some(Some((compare, limit, distinct)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holds(expression: &str, counts: &[u32]) -> bool {
        Expr::parse(expression).expect(expression).holds(counts)
    }

    #[test]
    fn and_or_and_groups() {
        assert!(holds("0&1&(2|3)", &[1, 1, 0, 4]));
        assert!(!holds("0&1&(2|3)", &[1, 1, 0, 0]));
        assert!(!holds("0&1&(2|3)", &[0, 1, 1, 1]));
        assert!(holds("0|1", &[0, 3]));
        assert!(!holds("0|1", &[0, 0]));
        assert!(holds("7", &[0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn counts_and_group_totals() {
        assert!(holds("0>2", &[3]));
        assert!(!holds("0>2", &[2]));
        assert!(holds("0=0&1", &[0, 1]));
        assert!(!holds("0=0&1", &[1, 1]));
        assert!(holds("0<2", &[1]));
        // Three matches between two sub-signatures, both of which matched.
        assert!(holds("(0|1)>2,2", &[2, 1]));
        assert!(!holds("(0|1)>2,2", &[3, 0]));
        assert!(holds("(0|1|2)>2", &[3, 0, 0]));
    }

    #[test]
    fn what_is_not_understood_is_refused() {
        for text in [
            "",
            "0&1|2",
            "0&",
            "&0",
            "(0&1",
            "0&1)",
            "x",
            "0>",
            "0>1,2",
            "99",
            "0 & 1",
            "0>99999999999",
        ] {
            assert!(Expr::parse(text).is_none(), "{text:?}");
        }
        let deep = format!("{}0{}", "(".repeat(40), ")".repeat(40));
        assert!(Expr::parse(&deep).is_none());
    }

    #[test]
    fn strength_is_the_weakest_way_to_satisfy_it() {
        let fixed = [10, 6, 4];
        let strength = |text: &str| Expr::parse(text).unwrap().required_bytes(&fixed);
        assert_eq!(strength("0"), 10);
        assert_eq!(strength("0&1"), 16);
        assert_eq!(strength("0|1"), 6);
        assert_eq!(strength("0&(1|2)"), 14);
        assert_eq!(strength("0=0"), 0);
        assert_eq!(strength("0<3"), 0);
        assert_eq!(strength("0>3"), 10);
        assert_eq!(strength("(0|1)>1"), 6);
    }

    #[test]
    fn subsignatures_are_listed() {
        let mut subs = Vec::new();
        Expr::parse("0&(1|2)>3&4").unwrap().subsignatures(&mut subs);
        subs.sort_unstable();
        assert_eq!(subs, [0, 1, 2, 4]);
    }
}

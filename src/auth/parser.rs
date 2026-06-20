//! Parsing and rendering of policy expressions like `pass1 or (pass2 and yk)`.
//!
//! Grammar (recursive descent), with `and` binding tighter than `or`:
//! ```text
//! expr   := or
//! or     := and ( "or"  and )*
//! and    := atom ( "and" atom )*
//! atom   := FACTOR | "(" expr ")"
//! ```
//! Factor names are alphanumeric with `-`/`_`; `and`/`or` are reserved keywords.

use std::collections::HashSet;

use anyhow::{Result, bail};

use super::policy::{Leaf, PolicyNode};

#[derive(Debug, PartialEq, Eq)]
enum Token {
    And,
    Or,
    LParen,
    RParen,
    Factor(String),
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            c if c.is_alphanumeric() || c == '-' || c == '_' => {
                let mut ident = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        ident.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match ident.to_ascii_lowercase().as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    _ => tokens.push(Token::Factor(ident)),
                }
            }
            other => bail!("unexpected character {other:?} in policy expression"),
        }
    }
    Ok(tokens)
}

/// Parses a policy expression into a [`PolicyNode`] (leaves carry the factor name
/// and an empty share). Use [`validate_factors`] to check the names exist.
pub fn parse_policy(input: &str) -> Result<PolicyNode> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        bail!("empty policy expression");
    }
    let mut pos = 0;
    let node = parse_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        bail!("unexpected trailing input in policy expression");
    }
    Ok(node)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<PolicyNode> {
    let mut children = vec![parse_and(tokens, pos)?];
    while tokens.get(*pos) == Some(&Token::Or) {
        *pos += 1;
        children.push(parse_and(tokens, pos)?);
    }
    Ok(if children.len() == 1 {
        children.swap_remove(0)
    } else {
        PolicyNode::Or(children)
    })
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<PolicyNode> {
    let mut children = vec![parse_atom(tokens, pos)?];
    while tokens.get(*pos) == Some(&Token::And) {
        *pos += 1;
        children.push(parse_atom(tokens, pos)?);
    }
    Ok(if children.len() == 1 {
        children.swap_remove(0)
    } else {
        PolicyNode::And(children)
    })
}

fn parse_atom(tokens: &[Token], pos: &mut usize) -> Result<PolicyNode> {
    match tokens.get(*pos) {
        Some(Token::Factor(name)) => {
            *pos += 1;
            Ok(PolicyNode::Leaf(Leaf {
                factor: name.clone(),
                wrapped_share: Vec::new(),
            }))
        }
        Some(Token::LParen) => {
            *pos += 1;
            let node = parse_or(tokens, pos)?;
            if tokens.get(*pos) != Some(&Token::RParen) {
                bail!("unclosed '(' in policy expression");
            }
            *pos += 1;
            Ok(node)
        }
        Some(_) => bail!("expected a factor name or '(' in policy expression"),
        None => bail!("unexpected end of policy expression"),
    }
}

/// Renders a policy tree to its canonical, re-parseable expression.
#[must_use]
pub fn render_policy(node: &PolicyNode) -> String {
    match node {
        PolicyNode::Leaf(leaf) => leaf.factor.clone(),
        PolicyNode::And(children) => join(children, " and ", node),
        PolicyNode::Or(children) => join(children, " or ", node),
    }
}

fn join(children: &[PolicyNode], sep: &str, parent: &PolicyNode) -> String {
    children
        .iter()
        .map(|child| {
            // Parenthesize a compound child of the opposite operator: required for
            // an OR inside an AND, and kept for readability for an AND inside an OR
            // (so `pass1 or (pass2 and yk)` renders as typed).
            let s = render_policy(child);
            if matches!(
                (parent, child),
                (PolicyNode::And(_), PolicyNode::Or(_)) | (PolicyNode::Or(_), PolicyNode::And(_))
            ) {
                format!("({s})")
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join(sep)
}

/// Errors if any leaf references a factor name not in `known`.
pub fn validate_factors(node: &PolicyNode, known: &HashSet<String>) -> Result<()> {
    let mut unknown = Vec::new();
    collect_unknown(node, known, &mut unknown);
    if unknown.is_empty() {
        Ok(())
    } else {
        unknown.sort();
        unknown.dedup();
        bail!(
            "policy references unknown factor(s): {}",
            unknown.join(", ")
        );
    }
}

fn collect_unknown(node: &PolicyNode, known: &HashSet<String>, unknown: &mut Vec<String>) {
    match node {
        PolicyNode::Leaf(leaf) => {
            if !known.contains(&leaf.factor) {
                unknown.push(leaf.factor.clone());
            }
        }
        PolicyNode::And(children) | PolicyNode::Or(children) => {
            for child in children {
                collect_unknown(child, known, unknown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(node: &PolicyNode) -> HashSet<String> {
        let mut s = HashSet::new();
        fn walk(n: &PolicyNode, s: &mut HashSet<String>) {
            match n {
                PolicyNode::Leaf(l) => {
                    s.insert(l.factor.clone());
                }
                PolicyNode::And(c) | PolicyNode::Or(c) => c.iter().for_each(|x| walk(x, s)),
            }
        }
        walk(node, &mut s);
        s
    }

    #[test]
    fn single_factor() {
        let p = parse_policy("pass1").unwrap();
        assert_eq!(render_policy(&p), "pass1");
    }

    #[test]
    fn and_binds_tighter_than_or() {
        let p = parse_policy("a or b and c").unwrap();
        assert_eq!(
            p,
            PolicyNode::Or(vec![
                PolicyNode::Leaf(Leaf {
                    factor: "a".into(),
                    wrapped_share: vec![]
                }),
                PolicyNode::And(vec![
                    PolicyNode::Leaf(Leaf {
                        factor: "b".into(),
                        wrapped_share: vec![]
                    }),
                    PolicyNode::Leaf(Leaf {
                        factor: "c".into(),
                        wrapped_share: vec![]
                    }),
                ]),
            ])
        );
    }

    #[test]
    fn parens_override_precedence() {
        let p = parse_policy("(a or b) and c").unwrap();
        assert_eq!(render_policy(&p), "(a or b) and c");
    }

    #[test]
    fn canonical_render_roundtrips() {
        for expr in [
            "pass1",
            "a or b",
            "a and b and c",
            "a or b and c",
            "(a or b) and c",
            "pass1 or (pass2 and yk-main)",
            "(a and b) or (c and d)",
            "((a or b) and c) or d",
        ] {
            let tree = parse_policy(expr).unwrap();
            let rendered = render_policy(&tree);
            let reparsed = parse_policy(&rendered).unwrap();
            assert_eq!(tree, reparsed, "expr={expr} rendered={rendered}");
        }
    }

    #[test]
    fn case_insensitive_keywords() {
        assert_eq!(
            parse_policy("a OR b").unwrap(),
            parse_policy("a or b").unwrap()
        );
        assert_eq!(
            parse_policy("a AND b").unwrap(),
            parse_policy("a and b").unwrap()
        );
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "a or",
            "a and",
            "(a",
            "a)",
            "a b",
            "a or or b",
            "and a",
            "a @ b",
        ] {
            assert!(parse_policy(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn validate_unknown_factor() {
        let p = parse_policy("a or (b and c)").unwrap();
        let known: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        assert!(validate_factors(&p, &known).is_err()); // c is unknown
        assert!(validate_factors(&p, &names(&p)).is_ok());
    }
}

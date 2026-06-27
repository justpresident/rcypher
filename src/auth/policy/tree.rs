//! The access-policy tree: a monotone boolean formula (`And`/`Or`/`Leaf`) over
//! factors.
//!
//! Leaves reference factors by their opaque [`FactorId`] only, so the tree is
//! agnostic to what a factor actually is. The user-facing, name-keyed form is a
//! separate [`PolicyExpr`] (the parser's product); the vault translates between the
//! two — [`PolicyExpr::resolve`] (names → ids) and [`PolicyNode::to_expr`] (ids →
//! names). The text syntax lives in the `parser` submodule; the secret sharing that
//! splits a key across the tree lives in `sharing`.

use std::collections::HashSet;

use anyhow::Result;
use bincode::{Decode, Encode};

use crate::auth::FactorId;

/// A monotone boolean access policy over named factors.
///
/// The data-encryption key is distributed down this tree by
/// [`distribute`](super::distribute): an [`Or`](PolicyNode::Or) replicates its
/// secret to each child, an [`And`](PolicyNode::And) XOR-splits it, and each
/// [`Leaf`] holds its share wrapped under the referenced factor's key.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub enum PolicyNode {
    /// Satisfied only when **all** children are satisfied.
    And(Vec<Self>),
    /// Satisfied when **any** child is satisfied.
    Or(Vec<Self>),
    /// A factor leaf.
    Leaf(Leaf),
}

/// A factor leaf: the [`FactorId`] of the factor that satisfies it, plus this
/// leaf's secret-share wrapped under that factor's key (empty until the DEK is
/// distributed across the policy).
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Leaf {
    /// Id of the enrolled factor (into the [`VaultHeader`](crate::auth::VaultHeader)
    /// factor table) that unlocks this leaf.
    pub factor: FactorId,
    /// This leaf's secret-share, encrypted under the factor's key.
    pub wrapped_share: Vec<u8>,
}

impl PolicyNode {
    /// Whether the set of `available` factor ids satisfies this policy.
    ///
    /// A pure boolean evaluation — `And` needs every child, `Or` needs any — used
    /// to drive the unlock UX (which factors to prompt for, and when enough have
    /// been collected) before doing any expensive key derivation.
    #[must_use]
    pub fn is_satisfied_by(&self, available: &HashSet<FactorId>) -> bool {
        match self {
            Self::Leaf(leaf) => available.contains(&leaf.factor),
            Self::And(children) => children.iter().all(|c| c.is_satisfied_by(available)),
            Self::Or(children) => children.iter().any(|c| c.is_satisfied_by(available)),
        }
    }

    /// Renders this stored tree as a name-keyed [`PolicyExpr`], resolving each
    /// leaf's opaque [`FactorId`] back to a name via `name_of` — the inverse of
    /// [`PolicyExpr::resolve`], for displaying the policy after unlock.
    pub fn to_expr(&self, name_of: &impl Fn(&FactorId) -> String) -> PolicyExpr {
        match self {
            Self::Leaf(leaf) => PolicyExpr::Leaf(name_of(&leaf.factor)),
            Self::And(children) => {
                PolicyExpr::And(children.iter().map(|c| c.to_expr(name_of)).collect())
            }
            Self::Or(children) => {
                PolicyExpr::Or(children.iter().map(|c| c.to_expr(name_of)).collect())
            }
        }
    }

    /// The leaves in left-to-right depth-first order — the one canonical order that
    /// secret-share distribution, share wrapping/unwrapping, and reconstruction all
    /// agree on. Centralizing it here keeps that cross-cutting invariant in a single
    /// place instead of re-encoded by hand at every traversal.
    pub fn leaves(&self) -> impl Iterator<Item = &Leaf> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                match node {
                    Self::Leaf(leaf) => return Some(leaf),
                    // Push children reversed so they pop left-to-right.
                    Self::And(children) | Self::Or(children) => stack.extend(children.iter().rev()),
                }
            }
            None
        })
    }

    /// The leaves, mutably, in the same left-to-right depth-first order as
    /// [`leaves`](Self::leaves) — for filling in or re-wrapping each leaf's share.
    pub fn leaves_mut(&mut self) -> impl Iterator<Item = &mut Leaf> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                match node {
                    Self::Leaf(leaf) => return Some(leaf),
                    Self::And(children) | Self::Or(children) => {
                        stack.extend(children.iter_mut().rev());
                    }
                }
            }
            None
        })
    }
}

/// A parsed access-policy expression over factor **names** — the user-facing,
/// textual form produced by [`parse_policy`](super::parse_policy) and rendered by
/// [`render_policy`](super::render_policy).
///
/// This is the name-keyed counterpart to the stored [`PolicyNode`], whose leaves
/// hold the opaque [`FactorId`] and the wrapped secret-shares. The two never mix:
/// the parser/renderer/validator work entirely in names, and the vault crosses the
/// boundary once via [`resolve`](Self::resolve) / [`PolicyNode::to_expr`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyExpr {
    /// Satisfied only when **all** children are satisfied.
    And(Vec<Self>),
    /// Satisfied when **any** child is satisfied.
    Or(Vec<Self>),
    /// A factor name.
    Leaf(String),
}

impl PolicyExpr {
    /// The factor names this expression references, in left-to-right depth-first
    /// order (the same order [`PolicyNode::leaves`] uses for the resolved tree).
    pub fn leaf_names(&self) -> impl Iterator<Item = &str> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                match node {
                    Self::Leaf(name) => return Some(name.as_str()),
                    Self::And(children) | Self::Or(children) => stack.extend(children.iter().rev()),
                }
            }
            None
        })
    }

    /// Resolves each name leaf to a [`FactorId`] via `lookup`, producing the stored
    /// [`PolicyNode`] with empty shares (ready for [`distribute`](super::distribute)
    /// to fill in). The inverse of [`PolicyNode::to_expr`].
    pub fn resolve(&self, lookup: &impl Fn(&str) -> Result<FactorId>) -> Result<PolicyNode> {
        Ok(match self {
            Self::Leaf(name) => PolicyNode::Leaf(Leaf {
                factor: lookup(name)?,
                wrapped_share: Vec::new(),
            }),
            Self::And(children) => PolicyNode::And(
                children
                    .iter()
                    .map(|c| c.resolve(lookup))
                    .collect::<Result<_>>()?,
            ),
            Self::Or(children) => PolicyNode::Or(
                children
                    .iter()
                    .map(|c| c.resolve(lookup))
                    .collect::<Result<_>>()?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str) -> PolicyNode {
        PolicyNode::Leaf(Leaf {
            factor: FactorId(name.as_bytes().to_vec()),
            wrapped_share: Vec::new(),
        })
    }

    #[test]
    fn is_satisfied_by_matches_boolean_logic() {
        // a OR (b AND c)
        let policy = PolicyNode::Or(vec![leaf("a"), PolicyNode::And(vec![leaf("b"), leaf("c")])]);
        let have = |ids: &[&str]| {
            ids.iter()
                .map(|s| FactorId(s.as_bytes().to_vec()))
                .collect::<HashSet<_>>()
        };

        assert!(policy.is_satisfied_by(&have(&["a"])));
        assert!(policy.is_satisfied_by(&have(&["b", "c"])));
        assert!(policy.is_satisfied_by(&have(&["a", "b"])));
        assert!(!policy.is_satisfied_by(&have(&["b"])));
        assert!(!policy.is_satisfied_by(&have(&["c"])));
        assert!(!policy.is_satisfied_by(&have(&[])));
    }
}

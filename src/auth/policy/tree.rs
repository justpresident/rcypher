//! The access-policy tree: a monotone boolean formula (`And`/`Or`/`Leaf`) over
//! named factors.
//!
//! Leaves reference factors by **id only**, so the tree is agnostic to what a
//! factor actually is. The text syntax lives in the `parser` submodule; the
//! secret sharing that splits a key across the tree lives in `sharing`.

use std::collections::HashSet;

use bincode::{Decode, Encode};

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

/// A factor leaf: the id of the factor that satisfies it, plus this leaf's
/// secret-share wrapped under that factor's key (empty until the DEK is
/// distributed across the policy).
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Leaf {
    /// Id of the enrolled factor (into the [`VaultHeader`](crate::auth::VaultHeader)
    /// factor table) that unlocks this leaf.
    pub factor: String,
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
    pub fn is_satisfied_by(&self, available: &HashSet<String>) -> bool {
        match self {
            Self::Leaf(leaf) => available.contains(&leaf.factor),
            Self::And(children) => children.iter().all(|c| c.is_satisfied_by(available)),
            Self::Or(children) => children.iter().any(|c| c.is_satisfied_by(available)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str) -> PolicyNode {
        PolicyNode::Leaf(Leaf {
            factor: name.into(),
            wrapped_share: Vec::new(),
        })
    }

    #[test]
    fn is_satisfied_by_matches_boolean_logic() {
        // a OR (b AND c)
        let policy = PolicyNode::Or(vec![leaf("a"), PolicyNode::And(vec![leaf("b"), leaf("c")])]);
        let have = |ids: &[&str]| ids.iter().map(|s| (*s).to_string()).collect::<HashSet<_>>();

        assert!(policy.is_satisfied_by(&have(&["a"])));
        assert!(policy.is_satisfied_by(&have(&["b", "c"])));
        assert!(policy.is_satisfied_by(&have(&["a", "b"])));
        assert!(!policy.is_satisfied_by(&have(&["b"])));
        assert!(!policy.is_satisfied_by(&have(&["c"])));
        assert!(!policy.is_satisfied_by(&have(&[])));
    }
}

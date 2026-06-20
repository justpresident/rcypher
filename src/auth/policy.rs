use std::collections::HashSet;

use anyhow::{Result, bail};
use bincode::{Decode, Encode};
use rand::TryRngCore;

/// A monotone boolean access policy over named factors.
///
/// The data-encryption key is distributed down this tree: [`PolicyNode::Or`]
/// replicates its secret to each child, [`PolicyNode::And`] XOR-splits it, and
/// each [`PolicyNode::Leaf`] holds its share wrapped under the referenced factor's
/// key. (The distribute/reconstruct algorithms live in the policy-engine task.)
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
    /// Id of the enrolled factor (into [`super::PolicyMetadata::factors`]) that
    /// unlocks this leaf.
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

/// XORs `other` into `acc` byte-wise (over the common length).
fn xor_into(acc: &mut [u8], other: &[u8]) {
    for (a, b) in acc.iter_mut().zip(other.iter()) {
        *a ^= b;
    }
}

/// Distributes `secret` across the policy tree, returning one share per leaf in
/// left-to-right depth-first order (the same order [`reconstruct`] consumes).
///
/// An [`PolicyNode::Or`] replicates its secret to every child; an
/// [`PolicyNode::And`] XOR-splits it into one independent share per child. Each
/// leaf receives the secret that reached it. The caller wraps each returned share
/// under its leaf's factor key.
pub fn distribute(secret: &[u8], node: &PolicyNode) -> Result<Vec<Vec<u8>>> {
    match node {
        PolicyNode::Leaf(_) => Ok(vec![secret.to_vec()]),
        PolicyNode::Or(children) => {
            if children.is_empty() {
                bail!("policy has an empty OR node");
            }
            let mut shares = Vec::new();
            for child in children {
                shares.extend(distribute(secret, child)?);
            }
            Ok(shares)
        }
        PolicyNode::And(children) => {
            if children.is_empty() {
                bail!("policy has an empty AND node");
            }
            // n-of-n XOR sharing: random shares for all but the last child, the
            // last carrying the residual so the XOR of all equals `secret`.
            let mut residual = secret.to_vec();
            let mut child_secrets: Vec<Vec<u8>> = Vec::with_capacity(children.len());
            for _ in 0..children.len() - 1 {
                let mut r = vec![0u8; secret.len()];
                rand::rngs::OsRng.try_fill_bytes(&mut r)?;
                xor_into(&mut residual, &r);
                child_secrets.push(r);
            }
            child_secrets.push(residual);

            let mut shares = Vec::new();
            for (child, child_secret) in children.iter().zip(child_secrets.iter()) {
                shares.extend(distribute(child_secret, child)?);
            }
            Ok(shares)
        }
    }
}

/// Reconstructs the secret from the shares the satisfied factors yielded.
///
/// `provided` has one slot per leaf, in [`distribute`] order: `Some(share)` if
/// that leaf's factor was satisfied (its share unwrapped), `None` otherwise.
/// Returns `Some(secret)` iff the policy is satisfied, `None` otherwise.
#[must_use]
pub fn reconstruct(node: &PolicyNode, provided: &[Option<Vec<u8>>]) -> Option<Vec<u8>> {
    let mut idx = 0;
    reconstruct_at(node, provided, &mut idx)
}

fn reconstruct_at(
    node: &PolicyNode,
    provided: &[Option<Vec<u8>>],
    idx: &mut usize,
) -> Option<Vec<u8>> {
    match node {
        PolicyNode::Leaf(_) => {
            let share = provided.get(*idx).and_then(Clone::clone);
            *idx += 1;
            share
        }
        PolicyNode::Or(children) => {
            // Every child is walked (to keep `idx` aligned), but any one satisfied
            // child yields the node's secret; keep the first.
            let mut result = None;
            for child in children {
                let value = reconstruct_at(child, provided, idx);
                if result.is_none() {
                    result = value;
                }
            }
            result
        }
        PolicyNode::And(children) => {
            // XOR all children's secrets; the node fails if any child is missing
            // (but we still walk every child to keep `idx` aligned).
            let mut acc: Option<Vec<u8>> = None;
            let mut all_present = true;
            for child in children {
                match reconstruct_at(child, provided, idx) {
                    Some(value) => {
                        acc = Some(match acc.take() {
                            None => value,
                            Some(mut a) => {
                                xor_into(&mut a, &value);
                                a
                            }
                        });
                    }
                    None => all_present = false,
                }
            }
            if all_present { acc } else { None }
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

    /// Ground-truth boolean evaluation of a policy against a per-leaf mask,
    /// walking every leaf to stay aligned with `distribute`/`reconstruct`.
    fn satisfied(node: &PolicyNode, mask: &[bool], idx: &mut usize) -> bool {
        match node {
            PolicyNode::Leaf(_) => {
                let v = mask[*idx];
                *idx += 1;
                v
            }
            PolicyNode::Or(children) => {
                let mut any = false;
                for c in children {
                    if satisfied(c, mask, idx) {
                        any = true;
                    }
                }
                any
            }
            PolicyNode::And(children) => {
                let mut all = true;
                for c in children {
                    if !satisfied(c, mask, idx) {
                        all = false;
                    }
                }
                all
            }
        }
    }

    /// For a policy, assert reconstruct succeeds iff the leaf subset satisfies it,
    /// and recovers exactly the secret when it does — across ALL leaf subsets.
    fn assert_exhaustive(policy: &PolicyNode) {
        let secret: Vec<u8> = (0..64u8).collect();
        let shares = distribute(&secret, policy).expect("distribute");
        let n = shares.len();
        assert!(n <= 16, "test policy too large to enumerate");

        for bits in 0u32..(1u32 << n) {
            let mask: Vec<bool> = (0..n).map(|i| (bits >> i) & 1 == 1).collect();
            let provided: Vec<Option<Vec<u8>>> = mask
                .iter()
                .zip(&shares)
                .map(|(&m, s)| if m { Some(s.clone()) } else { None })
                .collect();

            let mut idx = 0;
            let expected = satisfied(policy, &mask, &mut idx);
            let got = reconstruct(policy, &provided);

            assert_eq!(got.is_some(), expected, "policy={policy:?} mask={mask:?}");
            if expected {
                assert_eq!(got.as_deref(), Some(secret.as_slice()), "mask={mask:?}");
            }
        }
    }

    #[test]
    fn single_leaf() {
        assert_exhaustive(&leaf("a"));
    }

    #[test]
    fn flat_or() {
        assert_exhaustive(&PolicyNode::Or(vec![leaf("a"), leaf("b"), leaf("c")]));
    }

    #[test]
    fn flat_and() {
        assert_exhaustive(&PolicyNode::And(vec![leaf("a"), leaf("b"), leaf("c")]));
    }

    #[test]
    fn pass_or_pass_and_yubikey() {
        // a OR (b AND c)
        assert_exhaustive(&PolicyNode::Or(vec![
            leaf("a"),
            PolicyNode::And(vec![leaf("b"), leaf("c")]),
        ]));
    }

    #[test]
    fn and_of_or() {
        // (a OR b) AND c
        assert_exhaustive(&PolicyNode::And(vec![
            PolicyNode::Or(vec![leaf("a"), leaf("b")]),
            leaf("c"),
        ]));
    }

    #[test]
    fn deeply_nested() {
        // (a OR (b AND c)) AND (d OR e)
        assert_exhaustive(&PolicyNode::And(vec![
            PolicyNode::Or(vec![leaf("a"), PolicyNode::And(vec![leaf("b"), leaf("c")])]),
            PolicyNode::Or(vec![leaf("d"), leaf("e")]),
        ]));
    }

    #[test]
    fn empty_node_rejected() {
        assert!(distribute(&[0u8; 64], &PolicyNode::And(vec![])).is_err());
        assert!(distribute(&[0u8; 64], &PolicyNode::Or(vec![])).is_err());
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

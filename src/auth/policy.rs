use bincode::{Decode, Encode};

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

//! The vault header: the enrolled factors plus the access policy.
//!
//! This is the *locked*, serializable projection of a [`PolicyVault`] — the same
//! factors and policy, minus the recovered DEK. It is the cleartext header at the
//! front of a version-8 store file; its on-disk wire form (the container tag,
//! serialization, and the associated-data binding to the payload) lives in
//! [`crate::container::FileContainerV8`].
//!
//! [`PolicyVault`]: crate::auth::PolicyVault

use bincode::{Decode, Encode};

use super::factor::Factor;
use super::policy::{PolicyNode, render_policy};

/// The vault header stored ahead of the DEK-encrypted payload: the enrolled
/// factors and the access [`PolicyNode`] (whose leaves carry the wrapped shares).
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct VaultHeader {
    pub factors: Vec<Factor>,
    pub policy: PolicyNode,
}

impl VaultHeader {
    /// The access policy as a canonical, human-readable expression — e.g.
    /// `pass1 or (pass2 and yk)`. Lets a reader display the policy before unlock,
    /// without recovering the DEK.
    #[must_use]
    pub fn policy_expr(&self) -> String {
        render_policy(&self.policy)
    }
}

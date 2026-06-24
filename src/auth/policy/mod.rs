//! The access policy: the boolean tree over factor names ([`tree`]), its text
//! syntax ([`parser`]), and the secret sharing that splits the DEK across it
//! ([`sharing`]).
//!
//! The policy is **factor-agnostic** — it knows factors only by id — so this
//! whole subsystem is independent of the [`Factor`](crate::auth::Factor) model.

mod parser;
mod sharing;
mod tree;

pub use parser::{parse_policy, render_policy, validate_factors};
pub use sharing::{Share, distribute, reconstruct};
pub use tree::{Leaf, PolicyNode};

//! The access policy: the boolean tree over factors ([`tree`]), its text syntax
//! ([`parser`]), and the secret sharing that splits the DEK across it ([`sharing`]).
//!
//! The policy is **factor-agnostic** — it knows factors only by their opaque
//! [`FactorId`](crate::auth::FactorId), comparing them for identity and nothing
//! more — so this subsystem is independent of the [`Factor`](crate::auth::Factor)
//! model. The user-facing, name-keyed form is a separate [`PolicyExpr`].

mod parser;
mod sharing;
mod tree;

pub use parser::{is_factor_name_char, parse_policy, render_policy, validate_factors};
pub use sharing::{Share, distribute, reconstruct};
pub use tree::{Leaf, PolicyExpr, PolicyNode};

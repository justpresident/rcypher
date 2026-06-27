//! Reusable interactive CLI plumbing for building an rcypher-like command-line
//! tool on top of the library — behind the `cli` feature.
//!
//! These are deliberately opinionated terminal helpers: they prompt on and write
//! to the controlling terminal (`/dev/tty`) and stderr, keep secrets in zeroizing
//! buffers, and gate password strength with zxcvbn. The application keeps the rest
//! (argument parsing, any REPL, clipboard, etc.).
//!
//! - Prompts: [`prompt_password`], [`get_password`], [`prompt_new_password`],
//!   [`read_tty_confirmation`], and [`SecurePrinter`] (direct-to-tty secret output).
//! - [`confirm_if_weak_password`]: the zxcvbn strength gate.
//! - [`prompt_until_unlocked`]: the policy-unlock prompt loop over a
//!   [`LockedContainer`](crate::LockedContainer), with a pluggable
//!   [`UnlockProgress`] (a spinner, or [`NoProgress`]).

mod prompt;
mod strength;
mod unlock;

pub use prompt::{
    SecurePrinter, get_password, prompt_new_password, prompt_password, read_tty_confirmation,
};
pub use strength::confirm_if_weak_password;
pub use unlock::{NoProgress, UnlockProgress, prompt_until_unlocked};

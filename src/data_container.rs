//! [`DataContainer`]: what an encrypted container needs from your payload type.

use anyhow::Result;
use zeroize::Zeroizing;

use crate::crypto::Cypher;

/// Data stored inside an encrypted container.
///
/// The library owns the file, the lock (a password or a multi-factor policy), and
/// the AEAD envelope; from your type it only needs (de)serialization to bytes, plus
/// the [`rekey`](DataContainer::rekey)/[`verify`](DataContainer::verify) hooks for any inner
/// encryption it does itself.
///
/// `rekey`/`verify` have **no defaults on purpose**: a type that does its own inner
/// encryption under the container's [`cypher`](crate::UnlockedContainer::cypher)
/// *must* re-key it when a legacy file is upgraded, and a silent no-op default would
/// turn that omission into permanent data loss on upgrade. A payload that does no
/// inner encryption opts out explicitly with trivial bodies:
///
/// ```
/// # use rcypher::{DataContainer, Cypher, Result, Zeroizing};
/// # struct Plain(Vec<u8>);
/// impl DataContainer for Plain {
///     fn encode(&self) -> Result<Zeroizing<Vec<u8>>> { Ok(Zeroizing::new(self.0.clone())) }
///     fn decode(bytes: &[u8]) -> Result<Self> { Ok(Self(bytes.to_vec())) }
///     fn rekey(&mut self, _from: &Cypher, _to: &Cypher) -> Result<()> { Ok(()) }
///     fn verify(&self, _cypher: &Cypher) -> Result<()> { Ok(()) }
/// }
/// ```
pub trait DataContainer: Sized {
    /// Serializes to the cleartext bytes the container will encrypt. Returned in a
    /// zeroizing buffer, since they become the plaintext payload.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>>;

    /// Reconstructs from the decrypted payload bytes.
    fn decode(bytes: &[u8]) -> Result<Self>;

    /// Re-encrypts any data this type encrypted itself, from the `from` key to the
    /// `to` key. Called only when the container's data key changes — i.e. a legacy
    /// file is upgraded to the current format on unlock. A type with no inner
    /// encryption implements this as `Ok(())`.
    fn rekey(&mut self, from: &Cypher, to: &Cypher) -> Result<()>;

    /// Confirms this data is usable under `cypher` — every inner-encrypted value
    /// must decrypt. Called once at unlock, after any [`rekey`](DataContainer::rekey),
    /// so an inner re-key mistake surfaces immediately instead of on the next save.
    /// A type with no inner encryption implements this as `Ok(())`.
    fn verify(&self, cypher: &Cypher) -> Result<()>;
}

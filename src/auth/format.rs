use anyhow::{Result, bail};
use bincode::{Decode, Encode};

use super::policy::PolicyNode;
use crate::constants::SaltBytes;

/// Outer version tag for a policy-protected (multi-factor) vault.
///
/// It lives in the same leading 2-byte version space as a plain `V7` password
/// envelope (whose tag is 7), so a reader tells the two apart by probing the
/// first two bytes.
pub const POLICY_VAULT_VERSION: u16 = 8;

/// Key-derivation parameters for one enrolled factor.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub enum FactorKind {
    /// A passphrase factor: Argon2id over the password and a per-factor salt.
    Password {
        salt: SaltBytes,
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    },
    /// A FIDO2 security-key factor via the `hmac-secret` extension. `require_pin`
    /// asks the authenticator for user verification (a PIN) in addition to the
    /// touch that is always required.
    Yubikey {
        credential_id: Vec<u8>,
        rp_id: String,
        salt: SaltBytes,
        require_pin: bool,
    },
}

/// A named, enrolled factor and its derivation parameters.
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Factor {
    pub id: String,
    pub kind: FactorKind,
    /// This factor's auth-key (the 64-byte material it derives from its password
    /// or security key) encrypted under the DEK. It lets a holder of the unlocked
    /// DEK re-derive every factor's wrapping key — so the policy can be changed
    /// without presenting every factor again — while revealing nothing to an
    /// attacker who lacks the DEK.
    pub authkek_under_dek: Vec<u8>,
}

/// Keyslot metadata stored ahead of the DEK-encrypted payload: the enrolled
/// factors and the access [`PolicyNode`] (whose leaves carry the wrapped shares).
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub factors: Vec<Factor>,
    pub policy: PolicyNode,
}

impl PolicyMetadata {
    /// The access policy as a canonical, human-readable expression — e.g.
    /// `pass1 or (pass2 and yk)`. Lets a reader display the policy before unlock,
    /// without recovering the DEK.
    #[must_use]
    pub fn policy_expr(&self) -> String {
        super::parser::render_policy(&self.policy)
    }
}

/// Serializes a policy-vault header: the version tag followed by the bincoded
/// metadata. The caller appends the DEK-encrypted payload to the returned bytes.
pub fn serialize_policy_header(meta: &PolicyMetadata) -> Result<Vec<u8>> {
    let mut out = POLICY_VAULT_VERSION.to_be_bytes().to_vec();
    let encoded = bincode::encode_to_vec(meta, bincode::config::standard())?;
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// Splits a policy-vault blob into its metadata and the trailing DEK-encrypted
/// payload. Returns an error if `data` is not a policy vault.
pub fn parse_policy_vault(data: &[u8]) -> Result<(PolicyMetadata, &[u8])> {
    if data.len() < 2 {
        bail!("data too short for a policy vault");
    }
    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != POLICY_VAULT_VERSION {
        bail!("not a policy vault (version {version})");
    }
    let (meta, consumed): (PolicyMetadata, usize) =
        bincode::decode_from_slice(&data[2..], bincode::config::standard())?;
    Ok((meta, &data[2 + consumed..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::policy::{Leaf, PolicyNode};

    fn sample() -> PolicyMetadata {
        PolicyMetadata {
            factors: vec![
                Factor {
                    id: "pass1".into(),
                    kind: FactorKind::Password {
                        salt: [1u8; 32],
                        memory_cost: 65536,
                        time_cost: 3,
                        parallelism: 1,
                    },
                    authkek_under_dek: vec![10, 11, 12],
                },
                Factor {
                    id: "yk-main".into(),
                    kind: FactorKind::Yubikey {
                        credential_id: vec![9, 8, 7],
                        rp_id: "rcypher".into(),
                        salt: [2u8; 32],
                        require_pin: true,
                    },
                    authkek_under_dek: vec![13, 14],
                },
            ],
            // pass1 OR (pass1 AND yk-main)
            policy: PolicyNode::Or(vec![
                PolicyNode::Leaf(Leaf {
                    factor: "pass1".into(),
                    wrapped_share: vec![1, 2, 3],
                }),
                PolicyNode::And(vec![
                    PolicyNode::Leaf(Leaf {
                        factor: "pass1".into(),
                        wrapped_share: vec![4, 5],
                    }),
                    PolicyNode::Leaf(Leaf {
                        factor: "yk-main".into(),
                        wrapped_share: vec![6, 7, 8],
                    }),
                ]),
            ]),
        }
    }

    #[test]
    fn policy_vault_roundtrips_with_payload() {
        let meta = sample();
        let payload = b"DEK-encrypted-bytes";

        let mut blob = serialize_policy_header(&meta).unwrap();
        blob.extend_from_slice(payload);

        let (parsed, rest) = parse_policy_vault(&blob).unwrap();
        assert_eq!(parsed, meta);
        assert_eq!(rest, payload);
    }

    #[test]
    fn rejects_plain_v7_envelope() {
        // A plain password envelope starts with version 7, not 8.
        let blob = [0u8, 7, 0, 0, 0, 0];
        assert!(parse_policy_vault(&blob).is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse_policy_vault(&[8]).is_err());
    }
}

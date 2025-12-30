use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::{Argon2Params, Cypher, CypherVersion, EncryptionKey};

/// Master domain ID (uses the storage file password)
pub const MASTER_DOMAIN_ID: u32 = 0;

/// Master domain name
pub const MASTER_DOMAIN_NAME: &str = "master";

/// Encryption domain with a name and cypher
pub struct EncryptionDomain {
    pub name: String,
    pub cypher: Cypher,
}

impl EncryptionDomain {
    pub const fn new(name: String, cypher: Cypher) -> Self {
        Self { name, cypher }
    }
}

/// Manages encryption domains and their keys during a session.
///
/// Domain metadata (id -> name mapping) is stored in `StorageV5` and persisted to disk.
/// Domain keys (cyphers) are derived from passwords and stored only in memory during
/// the session. Users must re-enter passwords each session for maximum security.
pub struct EncryptionDomainManager {
    domains: HashMap<u32, EncryptionDomain>,
}

impl EncryptionDomainManager {
    /// Creates a new encryption domain manager with the master domain (domain 0)
    ///
    /// # Arguments
    /// * `master_cypher` - The cypher for domain 0 (derived from storage password)
    pub fn new(master_cypher: Cypher) -> Self {
        let mut domains = HashMap::new();
        domains.insert(
            MASTER_DOMAIN_ID,
            EncryptionDomain::new(MASTER_DOMAIN_NAME.to_string(), master_cypher),
        );
        Self { domains }
    }

    /// Unlocks an encryption domain by deriving a key from the provided password
    ///
    /// # Arguments
    /// * `domain_id` - The domain to unlock
    /// * `name` - Name of the domain (from `StorageV5` metadata)
    /// * `password` - Password to derive the domain key from
    /// * `argon2_params` - Argon2 parameters for key derivation
    ///
    /// # Errors
    /// * If the domain is already unlocked
    /// * If key derivation fails
    pub fn unlock_domain(
        &mut self,
        domain_id: u32,
        name: String,
        password: &str,
        argon2_params: &Argon2Params,
    ) -> Result<()> {
        if self.domains.contains_key(&domain_id) {
            bail!("Domain {domain_id} is already unlocked");
        }

        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            password,
            argon2_params,
        )?;

        let cypher = Cypher::new(key);
        self.domains
            .insert(domain_id, EncryptionDomain::new(name, cypher));

        Ok(())
    }

    /// Locks an encryption domain by removing its key from memory
    ///
    /// # Arguments
    /// * `domain_id` - The domain to lock
    ///
    /// # Errors
    /// * If the domain is not currently unlocked
    pub fn lock_domain(&mut self, domain_id: u32) -> Result<()> {
        if self.domains.remove(&domain_id).is_none() {
            bail!("Domain {domain_id} is not unlocked");
        }

        Ok(())
    }

    /// Checks if a domain is currently unlocked
    pub fn is_domain_unlocked(&self, domain_id: u32) -> bool {
        self.domains.contains_key(&domain_id)
    }

    /// Gets the cypher for a specific domain
    ///
    /// # Returns
    /// * `Some(&Cypher)` if the domain is unlocked
    /// * `None` if the domain is locked
    pub fn get_cypher(&self, domain_id: u32) -> Option<&Cypher> {
        self.domains.get(&domain_id).map(|d| &d.cypher)
    }

    /// Gets the encryption domain (name + cypher) for a specific domain
    ///
    /// # Returns
    /// * `Some(&EncryptionDomain)` if the domain is unlocked
    /// * `None` if the domain is locked
    pub fn get_domain(&self, domain_id: u32) -> Option<&EncryptionDomain> {
        self.domains.get(&domain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cypher() -> Cypher {
        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            "master_password",
            &Argon2Params::insecure(),
        )
        .unwrap();
        Cypher::new(key)
    }

    #[test]
    fn test_new_manager() {
        let cypher = create_test_cypher();
        let manager = EncryptionDomainManager::new(cypher);

        assert!(manager.is_domain_unlocked(MASTER_DOMAIN_ID));
        assert!(!manager.is_domain_unlocked(1));

        let master = manager.get_domain(MASTER_DOMAIN_ID).unwrap();
        assert_eq!(master.name, MASTER_DOMAIN_NAME);
    }

    #[test]
    fn test_unlock_domain() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        manager
            .unlock_domain(
                1,
                "work".to_string(),
                "domain1_password",
                &Argon2Params::insecure(),
            )
            .unwrap();

        assert!(manager.is_domain_unlocked(1));
        assert!(manager.get_cypher(1).is_some());

        let domain = manager.get_domain(1).unwrap();
        assert_eq!(domain.name, "work");
    }

    #[test]
    fn test_unlock_already_unlocked_fails() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        manager
            .unlock_domain(1, "test".to_string(), "password", &Argon2Params::insecure())
            .unwrap();

        let result =
            manager.unlock_domain(1, "test".to_string(), "password", &Argon2Params::insecure());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already unlocked"));
    }

    #[test]
    fn test_lock_domain() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        manager
            .unlock_domain(1, "test".to_string(), "password", &Argon2Params::insecure())
            .unwrap();
        assert!(manager.is_domain_unlocked(1));

        manager.lock_domain(1).unwrap();
        assert!(!manager.is_domain_unlocked(1));
        assert!(manager.get_cypher(1).is_none());
    }

    #[test]
    fn test_lock_master_domain() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        // Can lock master domain (no special treatment)
        manager.lock_domain(MASTER_DOMAIN_ID).unwrap();
        assert!(!manager.is_domain_unlocked(MASTER_DOMAIN_ID));
    }

    #[test]
    fn test_lock_not_unlocked_fails() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        let result = manager.lock_domain(1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not unlocked"));
    }

    #[test]
    fn test_multiple_domains() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        manager
            .unlock_domain(
                1,
                "personal".to_string(),
                "pass1",
                &Argon2Params::insecure(),
            )
            .unwrap();
        manager
            .unlock_domain(2, "work".to_string(), "pass2", &Argon2Params::insecure())
            .unwrap();
        manager
            .unlock_domain(3, "shared".to_string(), "pass3", &Argon2Params::insecure())
            .unwrap();

        assert!(manager.is_domain_unlocked(1));
        assert!(manager.is_domain_unlocked(2));
        assert!(manager.is_domain_unlocked(3));

        assert_eq!(manager.get_domain(1).unwrap().name, "personal");
        assert_eq!(manager.get_domain(2).unwrap().name, "work");
        assert_eq!(manager.get_domain(3).unwrap().name, "shared");

        manager.lock_domain(2).unwrap();

        assert!(manager.is_domain_unlocked(1));
        assert!(!manager.is_domain_unlocked(2));
        assert!(manager.is_domain_unlocked(3));
    }

    #[test]
    fn test_encrypt_decrypt_with_domain_key() {
        let cypher = create_test_cypher();
        let mut manager = EncryptionDomainManager::new(cypher);

        manager
            .unlock_domain(
                1,
                "test".to_string(),
                "domain_password",
                &Argon2Params::insecure(),
            )
            .unwrap();

        let domain_cypher = manager.get_cypher(1).unwrap();
        let plaintext = "secret data";

        let encrypted = domain_cypher.encrypt(plaintext.as_bytes()).unwrap();
        let decrypted = domain_cypher.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
    }
}

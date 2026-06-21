use crate::cli::Backend;
use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::DEFAULT_FACTOR_ID;
use crate::cli::completer::CypherCompleter;
use crate::cli::utils::{
    confirm_if_weak_password, copy_to_clipboard, format_timestamp, prompt_new_password,
    secure_print,
};
use anyhow::{Result, anyhow, bail};
use rcypher::{
    Argon2Params, EncryptedValue, FactorKind, PolicyVault, Storage, check_factor_password,
    is_debugger_attached,
};
use rustyline::CompletionType;
use rustyline::Config;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub struct InteractiveCli {
    prompt: String,
    insecure_stdout: bool,
    backend: Backend,
    argon2_params: Argon2Params,
    filename: PathBuf,
    /// Enrolled factor ids, shared with the completer so Tab completion of
    /// `remove factor` / `policy set` reflects enroll/remove.
    factors: Arc<Mutex<Vec<String>>>,
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
}

impl InteractiveCli {
    pub fn new(
        prompt: String,
        insecure_stdout: bool,
        backend: Backend,
        argon2_params: Argon2Params,
        filename: PathBuf,
        last_activity: Arc<AtomicU64>,
        last_security_check: Arc<AtomicU64>,
    ) -> Self {
        let factors = backend
            .policy_vault()
            .map(PolicyVault::factor_ids)
            .unwrap_or_default();
        Self {
            prompt,
            insecure_stdout,
            backend,
            argon2_params,
            filename,
            factors: Arc::new(Mutex::new(factors)),
            last_activity,
            last_security_check,
        }
    }

    /// Re-reads the enrolled factor ids into the shared completion list, so Tab
    /// completion stays in sync after `enroll` / `remove factor`.
    fn refresh_completion_factors(&self) {
        let ids = self
            .backend
            .policy_vault()
            .map(PolicyVault::factor_ids)
            .unwrap_or_default();
        *self.factors.lock().expect("able to lock factors") = ids;
    }

    pub fn run(&mut self) -> Result<()> {
        let storage = Arc::new(Mutex::new(self.backend.load_store(&self.filename)?));

        if self.backend.policy_vault().is_none() {
            eprintln!(
                "Note: this is a legacy single-password store. Run 'upgrade' to enable \
                 multi-factor unlock (factors, policies, YubiKey)."
            );
        }

        let config = Config::builder()
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .history_ignore_space(true)
            .history_ignore_dups(true)?
            .max_history_size(5)?
            .build();

        let completer = CypherCompleter::new(storage.clone(), self.factors.clone());
        let mut rl = Editor::with_config(config)?;
        rl.set_helper(Some(completer));

        // Signal to the security timer that idle timeout tracking has started
        self.last_activity
            .store(current_unix_secs(), Ordering::Relaxed);

        rl.clear_screen()?;
        loop {
            if is_debugger_attached() {
                bail!("Debugger detected");
            }

            let readline = rl.readline(&self.prompt);

            // Watchdog: if the security timer thread was paused (e.g. by a
            // debugger), its heartbeat will be stale. Exit rather than
            // allowing the session to continue without security enforcement.
            let secs_since_check = current_unix_secs()
                .saturating_sub(self.last_security_check.load(Ordering::Relaxed));
            if secs_since_check > crate::cli::SECURITY_WATCHDOG_TIMEOUT_SECS {
                clear_screen();
                bail!("Security heartbeat missed — exiting");
            }

            match readline {
                Ok(mut input_line) => {
                    let line = input_line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    rl.clear_screen()?;

                    let mut storage_guard = storage.lock().expect("able to lock");
                    if let Err(err) = self.process_cmd(line, &mut storage_guard) {
                        println!("{err}");
                    } else {
                        self.last_activity
                            .store(current_unix_secs(), Ordering::Relaxed);
                    }

                    input_line.zeroize();
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    println!("Error: {err:?}");
                    break;
                }
            }
        }

        drop(rl);
        clear_screen();

        Ok(())
    }

    fn process_cmd(&mut self, line: &str, storage: &mut Storage) -> Result<()> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let cmd = parts[0];
        match cmd {
            "put" => {
                if parts.len() < 3 {
                    bail!("syntax: put KEY VAL");
                }
                self.cmd_put(parts[1], parts[2], storage)
            }
            "get" => {
                if parts.len() < 2 {
                    bail!("syntax: get REGEXP");
                }
                self.cmd_get(parts[1], storage)
            }
            "copy" => {
                if parts.len() < 2 {
                    bail!("syntax: copy KEY");
                }
                self.cmd_copy(parts[1], storage)
            }
            "history" => {
                if parts.len() < 2 {
                    bail!("syntax: history KEY");
                }
                self.cmd_history(parts[1], storage)
            }
            "search" => {
                let pattern = if parts.len() > 1 { parts[1] } else { "" };
                self.cmd_search(pattern, storage)
            }
            "del" | "rm" => {
                if parts.len() < 2 {
                    bail!("syntax: del KEY");
                }
                self.cmd_delete(parts[1], storage)
            }
            "enroll" => self.cmd_enroll(&parts, storage),
            "factors" => self.cmd_factors(),
            "policy" => self.cmd_policy(&parts, storage),
            "remove" => self.cmd_remove(&parts, storage),
            "upgrade" => self.cmd_upgrade(storage),
            "help" => {
                print_help();
                Ok(())
            }
            _ => {
                bail!("No such command '{cmd}'\n");
            }
        }
    }

    fn cmd_put(&self, key: &str, value: &str, storage: &mut Storage) -> Result<()> {
        let encrypted_value = EncryptedValue::encrypt(self.backend.cypher(), value)?;
        storage.put(key.to_string(), encrypted_value);

        secure_print(format!("{key} stored"), self.insecure_stdout)?;

        self.backend.save_store(storage, &self.filename)?;
        Ok(())
    }

    fn cmd_get(&self, pattern: &str, storage: &Storage) -> Result<()> {
        match storage.get(pattern) {
            Ok(results) => {
                let mut found = false;
                for (key, val) in results {
                    found = true;
                    let mut secret = val.decrypt(self.backend.cypher())?;
                    let output = format!("{}: {}", key, &*secret);
                    secret.zeroize();
                    secure_print(output, self.insecure_stdout)?;
                }
                if !found {
                    bail!("No keys matching '{pattern}' found!");
                }
            }
            Err(e) => bail!("Error: {e}"),
        }
        Ok(())
    }

    fn cmd_copy(&self, key: &str, storage: &Storage) -> Result<()> {
        match storage.get(key) {
            Ok(mut results) => {
                let first = results.next();
                let second = results.next();

                match (first, second) {
                    (None, _) => bail!("No key '{key}' found!"),
                    (Some((first_key, _)), Some((second_key, _))) => {
                        // Multiple results - print all
                        println!("Multiple keys found! Plese specify exact key name:");
                        secure_print(first_key.to_string(), self.insecure_stdout)?;
                        secure_print(second_key.to_string(), self.insecure_stdout)?;
                        for (key, _) in results {
                            secure_print(key.to_string(), self.insecure_stdout)?;
                        }
                    }
                    (Some((_, val)), None) => {
                        // Exactly one result - copy to clipboard
                        let mut secret = val.decrypt(self.backend.cypher())?;
                        copy_to_clipboard(
                            secret.as_ref(),
                            std::time::Duration::from_millis(CLIPBOARD_TTL_MS),
                        );
                        secret.zeroize();
                    }
                }
            }
            Err(e) => bail!("Error: {e}"),
        }
        Ok(())
    }

    fn cmd_history(&self, key: &str, storage: &Storage) -> Result<()> {
        if let Some(entries) = storage.history(key) {
            for entry in entries {
                let mut secret = entry.value.decrypt(self.backend.cypher())?;
                let output = format!("[{}]: {}", format_timestamp(entry.timestamp), &*secret);
                secret.zeroize();
                secure_print(output, self.insecure_stdout)?;
            }
        } else {
            bail!("No key '{key}' found!");
        }
        Ok(())
    }

    fn cmd_search(&self, pattern: &str, storage: &Storage) -> Result<()> {
        match storage.search(pattern) {
            Ok(keys) => {
                for key in keys {
                    secure_print(key.to_string(), self.insecure_stdout)?;
                }
            }
            Err(e) => bail!("Error: {e}"),
        }
        Ok(())
    }

    fn cmd_delete(&self, key: &str, storage: &mut Storage) -> Result<()> {
        if storage.delete(key) {
            secure_print(format!("{key} deleted"), self.insecure_stdout)?;
            self.backend.save_store(storage, &self.filename)?;
        } else {
            bail!("No such key '{key}' found");
        }
        Ok(())
    }

    /// `enroll password NAME` — add a new password factor (prompted, with
    /// confirmation). `NAME` is a label, not the password; the password is
    /// prompted separately. The new factor is not used by the policy until a
    /// `policy set` references it.
    fn cmd_enroll(&mut self, parts: &[&str], storage: &Storage) -> Result<()> {
        match parts.get(1).copied() {
            Some("password") => {
                let id = parts
                    .get(2)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("syntax: enroll password NAME (NAME is a label)"))?;
                self.enroll_password(id, storage)
            }
            Some("yubikey") => bail!("YubiKey enrollment is not yet supported"),
            _ => bail!("syntax: enroll password NAME (NAME is a label, not the password)"),
        }
    }

    fn enroll_password(&mut self, id: &str, storage: &Storage) -> Result<()> {
        // Make the role of NAME explicit: it is a public label, not the secret.
        // Catches the mix-up of typing a password where the factor name belongs.
        secure_print(
            format!(
                "Enrolling factor '{id}'. The name is a public label (shown by 'factors', \
                 stored unencrypted) — not the password; you'll enter the password next."
            ),
            self.insecure_stdout,
        )?;
        // The password is held in a zeroizing buffer, so every early return below
        // wipes it on drop; it is also wiped eagerly once the factor is enrolled.
        let mut password = prompt_new_password(&format!("factor '{id}'"))?;

        // Reject a password that resembles the (cleartext) name first, so that
        // mix-up gets its specific message rather than a generic strength warning.
        check_factor_password(id, &password)?;
        if !confirm_if_weak_password(&password, &[id, "rcypher"])? {
            bail!("enrollment cancelled (weak password not confirmed)");
        }

        let params = self.argon2_params;
        self.backend
            .policy_vault_mut()
            .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage — run 'upgrade' to convert this legacy store to a policy vault"))?
            .enroll_password(id, &password, &params)?;
        password.zeroize(); // wipe as soon as the factor's key material is derived

        self.backend.save_store(storage, &self.filename)?;
        self.refresh_completion_factors();
        secure_print(
            format!(
                "Factor '{id}' enrolled. It is not yet used by the policy — run \
                 'policy set EXPR' to require or accept it."
            ),
            self.insecure_stdout,
        )?;
        Ok(())
    }

    /// `factors` — list the enrolled factors and their kinds.
    fn cmd_factors(&self) -> Result<()> {
        let vault = self
            .backend
            .policy_vault()
            .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage — run 'upgrade' to convert this legacy store to a policy vault"))?;
        for factor in vault.metadata().factors {
            let kind = match factor.kind {
                FactorKind::Password { .. } => "password",
                FactorKind::Yubikey { .. } => "yubikey",
            };
            secure_print(format!("{} ({kind})", factor.id), self.insecure_stdout)?;
        }
        Ok(())
    }

    /// `policy` / `policy show` — print the policy; `policy set EXPR` — replace it.
    fn cmd_policy(&mut self, parts: &[&str], storage: &Storage) -> Result<()> {
        match parts.get(1).copied() {
            None | Some("show") => {
                let vault = self
                    .backend
                    .policy_vault()
                    .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage — run 'upgrade' to convert this legacy store to a policy vault"))?;
                secure_print(vault.policy_expr(), self.insecure_stdout)
            }
            Some("set") => {
                let expr = parts
                    .get(2)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("syntax: policy set EXPR"))?;
                self.set_policy(expr, storage)
            }
            Some(other) => bail!("unknown policy subcommand '{other}' (try: policy show|set EXPR)"),
        }
    }

    fn set_policy(&mut self, expr: &str, storage: &Storage) -> Result<()> {
        let new_expr = {
            let vault = self
                .backend
                .policy_vault_mut()
                .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage — run 'upgrade' to convert this legacy store to a policy vault"))?;
            vault.set_policy(expr)?;
            vault.policy_expr()
        };
        self.backend.save_store(storage, &self.filename)?;
        secure_print(format!("Policy: {new_expr}"), self.insecure_stdout)?;
        Ok(())
    }

    /// `remove factor NAME` — drop a factor (must not be referenced by the policy).
    fn cmd_remove(&mut self, parts: &[&str], storage: &Storage) -> Result<()> {
        match parts.get(1).copied() {
            Some("factor") => {
                let id = parts
                    .get(2)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("syntax: remove factor NAME"))?;
                {
                    let vault = self.backend.policy_vault_mut().ok_or_else(|| {
                        anyhow!("this store has no multi-factor policy to manage — run 'upgrade' to convert this legacy store to a policy vault")
                    })?;
                    vault.remove_factor(id)?;
                }
                self.backend.save_store(storage, &self.filename)?;
                self.refresh_completion_factors();
                secure_print(format!("Factor '{id}' removed"), self.insecure_stdout)
            }
            _ => bail!("syntax: remove factor NAME"),
        }
    }

    /// `upgrade` — convert a legacy single-password store into a multi-factor
    /// policy vault. The entered password becomes the first factor, `primary`,
    /// and every stored value is re-encrypted under the vault's fresh key.
    fn cmd_upgrade(&mut self, storage: &mut Storage) -> Result<()> {
        if self.backend.policy_vault().is_some() {
            bail!("this store is already a multi-factor policy vault");
        }

        secure_print(
            "Upgrading this legacy store to a multi-factor policy vault. The password you set \
             next becomes the first factor, 'primary'."
                .to_string(),
            self.insecure_stdout,
        )?;

        let mut password = prompt_new_password("the upgraded store (factor 'primary')")?;
        check_factor_password(DEFAULT_FACTOR_ID, &password)?;
        if !confirm_if_weak_password(&password, &[DEFAULT_FACTOR_ID, "rcypher"])? {
            bail!("upgrade cancelled (weak password not confirmed)");
        }

        let vault = PolicyVault::create(DEFAULT_FACTOR_ID, &password, &self.argon2_params)?;
        password.zeroize(); // wipe as soon as the vault's key material is derived
        let new_cypher = vault.cypher();

        // Re-encrypt every stored value from the legacy key to the new DEK, in the
        // in-memory store, before swapping the backend.
        {
            let old_cypher = self.backend.cypher();
            for entries in storage.data.values_mut() {
                for entry in entries {
                    let plaintext = entry.value.decrypt(old_cypher)?;
                    entry.value = EncryptedValue::encrypt(&new_cypher, &plaintext)?;
                }
            }
        }

        self.backend = Backend::Policy {
            vault,
            cypher: new_cypher,
        };
        self.backend.save_store(storage, &self.filename)?;
        self.refresh_completion_factors();

        secure_print(
            "Upgraded to a multi-factor policy vault. Enrolled factor 'primary'; use \
             'enroll'/'policy' to add more."
                .to_string(),
            self.insecure_stdout,
        )?;
        Ok(())
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // Clear screen
}

fn print_help() {
    println!("USER COMMANDS:");
    println!("  put KEY VAL     - Store a key-value pair");
    println!("  get REGEXP      - Get values for keys matching regexp");
    println!("  copy KEY        - Copy key value into system clipboard");
    println!("  history KEY     - Show history of changes for a key");
    println!("  search REGEXP   - Search for keys matching regexp");
    println!("  del|rm KEY      - Delete a key");
    println!("  help            - Show this help");
    println!();
    println!("AUTH COMMANDS (multi-factor stores):");
    println!("  upgrade             - Convert a legacy single-password store to a policy vault");
    println!("  factors             - List enrolled factors");
    println!(
        "  enroll password NAME - Enroll a new password factor (NAME is a label, not the password)"
    );
    println!("  policy show         - Show the current unlock policy");
    println!("  policy set EXPR     - Set the unlock policy, e.g. p1 or (p2 and yk)");
    println!("  remove factor NAME  - Remove a factor (not used by the policy)");
}

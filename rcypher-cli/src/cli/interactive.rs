use crate::cli::Backend;
use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::completer::CypherCompleter;
use crate::cli::utils::{
    copy_to_clipboard, format_timestamp, prompt_new_password, secure_print,
    warn_single_password_unlock,
};
use anyhow::{Result, anyhow, bail};
use rcypher::{Argon2Params, EncryptedValue, FactorKind, Storage, is_debugger_attached};
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
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
}

impl InteractiveCli {
    pub const fn new(
        prompt: String,
        insecure_stdout: bool,
        backend: Backend,
        argon2_params: Argon2Params,
        filename: PathBuf,
        last_activity: Arc<AtomicU64>,
        last_security_check: Arc<AtomicU64>,
    ) -> Self {
        Self {
            prompt,
            insecure_stdout,
            backend,
            argon2_params,
            filename,
            last_activity,
            last_security_check,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let storage = Arc::new(Mutex::new(self.backend.load_store(&self.filename)?));

        let config = Config::builder()
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .history_ignore_space(true)
            .history_ignore_dups(true)?
            .max_history_size(5)?
            .build();

        let completer = CypherCompleter::new(storage.clone());
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
    /// confirmation). The new factor is not used by the policy until a
    /// `policy set` references it.
    fn cmd_enroll(&mut self, parts: &[&str], storage: &Storage) -> Result<()> {
        match parts.get(1).copied() {
            Some("password") => {
                let id = parts
                    .get(2)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("syntax: enroll password NAME"))?;
                self.enroll_password(id, storage)
            }
            Some("yubikey") => bail!("YubiKey enrollment is not yet supported"),
            _ => bail!("syntax: enroll password NAME"),
        }
    }

    fn enroll_password(&mut self, id: &str, storage: &Storage) -> Result<()> {
        let mut password = prompt_new_password(&format!("factor '{id}'"))?;
        let params = self.argon2_params;
        let result = self
            .backend
            .policy_vault_mut()
            .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage"))
            .and_then(|vault| vault.enroll_password(id, &password, &params));
        password.zeroize();
        result?;

        self.backend.save_store(storage, &self.filename)?;
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
            .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage"))?;
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
                    .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage"))?;
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
        let (new_expr, weak) = {
            let vault = self
                .backend
                .policy_vault_mut()
                .ok_or_else(|| anyhow!("this store has no multi-factor policy to manage"))?;
            vault.set_policy(expr)?;
            (
                vault.policy_expr(),
                vault.metadata().single_password_unlockers(),
            )
        };
        self.backend.save_store(storage, &self.filename)?;
        secure_print(format!("Policy: {new_expr}"), self.insecure_stdout)?;
        warn_single_password_unlock(&weak);
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
                        anyhow!("this store has no multi-factor policy to manage")
                    })?;
                    vault.remove_factor(id)?;
                }
                self.backend.save_store(storage, &self.filename)?;
                secure_print(format!("Factor '{id}' removed"), self.insecure_stdout)
            }
            _ => bail!("syntax: remove factor NAME"),
        }
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
    println!("  factors             - List enrolled factors");
    println!("  enroll password NAME - Enroll a new password factor");
    println!("  policy show         - Show the current unlock policy");
    println!("  policy set EXPR     - Set the unlock policy, e.g. p1 or (p2 and yk)");
    println!("  remove factor NAME  - Remove a factor (not used by the policy)");
}

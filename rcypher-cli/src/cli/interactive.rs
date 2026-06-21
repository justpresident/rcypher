use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::completer::CypherCompleter;
use crate::cli::persist_store;
use crate::cli::utils::{
    confirm_if_weak_password, copy_to_clipboard, format_timestamp, prompt_new_password,
    secure_print,
};
use anyhow::{Result, anyhow, bail};
use rcypher::{
    Argon2Params, Cypher, EncryptedValue, FactorKind, PolicyVault, Storage, check_factor_password,
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
    /// The unlocked store's auth keyslots and access policy. Every store carries
    /// one in memory (legacy files are converted on open).
    vault: PolicyVault,
    /// A `Cypher` keyed by the vault's (stable) DEK, for per-value crypto.
    cypher: Cypher,
    /// True while the store was opened from a legacy file and hasn't yet been
    /// rewritten in the current format; the first save backs up the original.
    pending_legacy_backup: bool,
    argon2_params: Argon2Params,
    filename: PathBuf,
    /// Enrolled factor ids, shared with the completer so Tab completion of
    /// `auth factor remove` / `auth policy set` reflects add/remove.
    factors: Arc<Mutex<Vec<String>>>,
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
}

impl InteractiveCli {
    pub fn new(
        prompt: String,
        insecure_stdout: bool,
        vault: PolicyVault,
        from_legacy: bool,
        argon2_params: Argon2Params,
        filename: PathBuf,
        clock: crate::SecurityClock,
    ) -> Self {
        let factors = vault.factor_ids();
        let cypher = vault.cypher();
        Self {
            prompt,
            insecure_stdout,
            vault,
            cypher,
            pending_legacy_backup: from_legacy,
            argon2_params,
            filename,
            factors: Arc::new(Mutex::new(factors)),
            last_activity: clock.last_activity,
            last_security_check: clock.last_security_check,
        }
    }

    /// Re-reads the enrolled factor ids into the shared completion list, so Tab
    /// completion stays in sync after `auth factor add` / `remove`.
    fn refresh_completion_factors(&self) {
        *self.factors.lock().expect("able to lock factors") = self.vault.factor_ids();
    }

    /// Writes the store, backing up the original legacy file on the first save.
    fn save(&mut self, storage: &Storage) -> Result<()> {
        persist_store(
            &self.vault,
            storage,
            &self.filename,
            self.pending_legacy_backup,
        )?;
        self.pending_legacy_backup = false;
        Ok(())
    }

    pub fn run(mut self, storage: Storage) -> Result<()> {
        let storage = Arc::new(Mutex::new(storage));

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
            "auth" => self.cmd_auth(line, storage),
            "help" => {
                print_help();
                Ok(())
            }
            _ => {
                bail!("No such command '{cmd}'\n");
            }
        }
    }

    fn cmd_put(&mut self, key: &str, value: &str, storage: &mut Storage) -> Result<()> {
        let encrypted_value = EncryptedValue::encrypt(&self.cypher, value)?;
        storage.put(key.to_string(), encrypted_value);

        secure_print(format!("{key} stored"), self.insecure_stdout)?;

        self.save(storage)?;
        Ok(())
    }

    fn cmd_get(&self, pattern: &str, storage: &Storage) -> Result<()> {
        match storage.get(pattern) {
            Ok(results) => {
                let mut found = false;
                for (key, val) in results {
                    found = true;
                    let mut secret = val.decrypt(&self.cypher)?;
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
                        let mut secret = val.decrypt(&self.cypher)?;
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
                let mut secret = entry.value.decrypt(&self.cypher)?;
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

    fn cmd_delete(&mut self, key: &str, storage: &mut Storage) -> Result<()> {
        if storage.delete(key) {
            secure_print(format!("{key} deleted"), self.insecure_stdout)?;
            self.save(storage)?;
        } else {
            bail!("No such key '{key}' found");
        }
        Ok(())
    }

    /// `auth …` — multi-factor management. Subcommands: `auth policy {show|set
    /// EXPR}` and `auth factor {list|add password NAME|add yubikey NAME|remove
    /// NAME}`.
    fn cmd_auth(&mut self, line: &str, storage: &Storage) -> Result<()> {
        let args = line.strip_prefix("auth").unwrap_or("").trim_start();
        let (sub, rest) = split_first_word(args);
        match sub {
            "policy" => self.cmd_auth_policy(rest, storage),
            "factor" => self.cmd_auth_factor(rest, storage),
            "" => {
                print_auth_help();
                Ok(())
            }
            other => bail!("unknown auth subcommand '{other}' (try: auth policy|factor)"),
        }
    }

    fn cmd_auth_policy(&mut self, args: &str, storage: &Storage) -> Result<()> {
        let (verb, rest) = split_first_word(args);
        match verb {
            "" | "show" => {
                let expr = self.vault.policy_expr();
                secure_print(expr, self.insecure_stdout)
            }
            "set" => {
                if rest.is_empty() {
                    bail!("syntax: auth policy set EXPR");
                }
                self.set_policy(rest, storage)
            }
            other => bail!("unknown 'auth policy' subcommand '{other}' (try: show | set EXPR)"),
        }
    }

    fn cmd_auth_factor(&mut self, args: &str, storage: &Storage) -> Result<()> {
        let (verb, rest) = split_first_word(args);
        match verb {
            "list" => self.list_factors(),
            "add" => self.cmd_auth_factor_add(rest, storage),
            "remove" => {
                let id =
                    first_word(rest).ok_or_else(|| anyhow!("syntax: auth factor remove NAME"))?;
                self.remove_factor(id, storage)
            }
            "" => bail!("syntax: auth factor list|add|remove …"),
            other => {
                bail!("unknown 'auth factor' subcommand '{other}' (try: list | add | remove NAME)")
            }
        }
    }

    fn cmd_auth_factor_add(&mut self, args: &str, storage: &Storage) -> Result<()> {
        let (kind, rest) = split_first_word(args);
        match kind {
            "password" => {
                let id = first_word(rest).ok_or_else(|| {
                    anyhow!("syntax: auth factor add password NAME (NAME is a label)")
                })?;
                self.enroll_password(id, storage)
            }
            "yubikey" => bail!("YubiKey enrollment is not yet supported"),
            _ => bail!("syntax: auth factor add password|yubikey NAME"),
        }
    }

    /// Lists the enrolled factors and their kinds.
    fn list_factors(&self) -> Result<()> {
        for factor in self.vault.metadata().factors {
            let kind = match factor.kind {
                FactorKind::Password { .. } => "password",
                FactorKind::Yubikey { .. } => "yubikey",
            };
            secure_print(format!("{} ({kind})", factor.id), self.insecure_stdout)?;
        }
        Ok(())
    }

    /// Adds a new password factor. `id` is a public label, not the password; the
    /// password is prompted separately. The factor is unused by the policy until
    /// an `auth policy set` references it.
    fn enroll_password(&mut self, id: &str, storage: &Storage) -> Result<()> {
        // Make the role of NAME explicit: it is a public label, not the secret.
        // Catches the mix-up of typing a password where the factor name belongs.
        secure_print(
            format!(
                "Enrolling factor '{id}'. The name is a public label (shown by 'auth factor \
                 list', stored unencrypted) — not the password; you'll enter the password next."
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
        self.vault.enroll_password(id, &password, &params)?;
        password.zeroize(); // wipe as soon as the factor's key material is derived

        self.save(storage)?;
        self.refresh_completion_factors();
        secure_print(
            format!(
                "Factor '{id}' enrolled. It is not yet used by the policy — run \
                 'auth policy set EXPR' to require or accept it."
            ),
            self.insecure_stdout,
        )?;
        Ok(())
    }

    fn set_policy(&mut self, expr: &str, storage: &Storage) -> Result<()> {
        let new_expr = {
            let vault = &mut self.vault;
            vault.set_policy(expr)?;
            vault.policy_expr()
        };
        self.save(storage)?;
        secure_print(format!("Policy: {new_expr}"), self.insecure_stdout)?;
        Ok(())
    }

    /// Drops a factor (must not be referenced by the policy).
    fn remove_factor(&mut self, id: &str, storage: &Storage) -> Result<()> {
        {
            let vault = &mut self.vault;
            vault.remove_factor(id)?;
        }
        self.save(storage)?;
        self.refresh_completion_factors();
        secure_print(format!("Factor '{id}' removed"), self.insecure_stdout)
    }
}

/// Splits off the first whitespace-delimited word, returning it and the trimmed
/// remainder (which may contain spaces, e.g. a policy expression).
fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    s.find(char::is_whitespace)
        .map_or((s, ""), |i| (&s[..i], s[i..].trim_start()))
}

/// The first whitespace-delimited word of `s`, if any.
fn first_word(s: &str) -> Option<&str> {
    s.split_whitespace().next()
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
    print_auth_help();
}

fn print_auth_help() {
    println!("AUTH COMMANDS (multi-factor stores):");
    println!("  auth factor list           - List enrolled factors");
    println!(
        "  auth factor add password NAME - Add a password factor (NAME is a label, not the password)"
    );
    println!("  auth factor remove NAME    - Remove a factor (not used by the policy)");
    println!("  auth policy show           - Show the current unlock policy");
    println!("  auth policy set EXPR       - Set the unlock policy, e.g. p1 or (p2 and yk)");
}

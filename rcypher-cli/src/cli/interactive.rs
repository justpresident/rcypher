use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::completer::CypherCompleter;
use crate::cli::utils::{copy_to_clipboard, format_timestamp};
use anyhow::{Result, anyhow, bail};
use rcypher::cli::{confirm_if_weak_password, prompt_new_password, secure_print};
use rcypher::{EncryptedValue, FactorKind, check_factor_password, is_debugger_attached};
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
    /// The opened, unlocked store ([`UnlockedContainer`](rcypher::UnlockedContainer))
    /// behind one lock shared with the Tab completer, which reads keys and factor
    /// names from it live. Saving and the one-time legacy-upgrade backup are the
    /// store's own responsibility.
    store: Arc<Mutex<crate::Store>>,
    filename: PathBuf,
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
}

impl InteractiveCli {
    pub fn new(
        prompt: String,
        insecure_stdout: bool,
        store: crate::Store,
        filename: PathBuf,
        clock: crate::SecurityClock,
    ) -> Self {
        Self {
            prompt,
            insecure_stdout,
            store: Arc::new(Mutex::new(store)),
            filename,
            last_activity: clock.last_activity,
            last_security_check: clock.last_security_check,
        }
    }

    /// Writes the store in the current format. The facade backs up the original
    /// file to `<path>.bak` on the first save of a legacy store it upgraded.
    fn save(&self, store: &mut crate::Store) -> Result<()> {
        store.save(&self.filename)
    }

    pub fn run(self) -> Result<()> {
        let config = Config::builder()
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .history_ignore_space(true)
            .history_ignore_dups(true)?
            .max_history_size(5)?
            .build();

        // The completer shares the same locked store, so Tab completion reads the
        // current keys and factor names directly.
        let completer = CypherCompleter::new(Arc::clone(&self.store));
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

                    if let Err(err) = self.process_cmd(line) {
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

    fn process_cmd(&self, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let cmd = parts[0];
        let mut store = self.store.lock().expect("able to lock store");
        match cmd {
            "put" => {
                if parts.len() < 3 {
                    bail!("syntax: put KEY VAL");
                }
                self.cmd_put(parts[1], parts[2], &mut store)
            }
            "get" => {
                if parts.len() < 2 {
                    bail!("syntax: get REGEXP");
                }
                self.cmd_get(parts[1], &store)
            }
            "copy" => {
                if parts.len() < 2 {
                    bail!("syntax: copy KEY");
                }
                self.cmd_copy(parts[1], &store)
            }
            "history" => {
                if parts.len() < 2 {
                    bail!("syntax: history KEY");
                }
                self.cmd_history(parts[1], &store)
            }
            "search" => {
                let pattern = if parts.len() > 1 { parts[1] } else { "" };
                self.cmd_search(pattern, &store)
            }
            "del" | "rm" => {
                if parts.len() < 2 {
                    bail!("syntax: del KEY");
                }
                self.cmd_delete(parts[1], &mut store)
            }
            "auth" => self.cmd_auth(line, &mut store),
            "help" => {
                print_help();
                Ok(())
            }
            _ => {
                bail!("No such command '{cmd}'\n");
            }
        }
    }

    fn cmd_put(&self, key: &str, value: &str, store: &mut crate::Store) -> Result<()> {
        let encrypted_value = EncryptedValue::encrypt(&store.cypher(), value)?;
        store.data_mut().put(key.to_string(), encrypted_value);

        secure_print(format!("{key} stored"), self.insecure_stdout)?;

        self.save(store)?;
        Ok(())
    }

    fn cmd_get(&self, pattern: &str, store: &crate::Store) -> Result<()> {
        let cypher = store.cypher();
        match store.data().get(pattern) {
            Ok(results) => {
                let mut found = false;
                for (key, val) in results {
                    found = true;
                    let mut secret = val.decrypt(&cypher)?;
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

    fn cmd_copy(&self, key: &str, store: &crate::Store) -> Result<()> {
        match store.data().get(key) {
            Ok(mut results) => {
                let first = results.next();
                let second = results.next();

                match (first, second) {
                    (None, _) => bail!("No key '{key}' found!"),
                    (Some((first_key, _)), Some((second_key, _))) => {
                        // Multiple results - print all
                        println!("Multiple keys found! Please specify exact key name:");
                        secure_print(first_key.to_string(), self.insecure_stdout)?;
                        secure_print(second_key.to_string(), self.insecure_stdout)?;
                        for (key, _) in results {
                            secure_print(key.to_string(), self.insecure_stdout)?;
                        }
                    }
                    (Some((_, val)), None) => {
                        // Exactly one result - copy to clipboard
                        let mut secret = val.decrypt(&store.cypher())?;
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

    fn cmd_history(&self, key: &str, store: &crate::Store) -> Result<()> {
        let cypher = store.cypher();
        if let Some(entries) = store.data().history(key) {
            for entry in entries {
                let mut secret = entry.value.decrypt(&cypher)?;
                let output = format!("[{}]: {}", format_timestamp(entry.timestamp), &*secret);
                secret.zeroize();
                secure_print(output, self.insecure_stdout)?;
            }
        } else {
            bail!("No key '{key}' found!");
        }
        Ok(())
    }

    fn cmd_search(&self, pattern: &str, store: &crate::Store) -> Result<()> {
        match store.data().search(pattern) {
            Ok(keys) => {
                for key in keys {
                    secure_print(key.to_string(), self.insecure_stdout)?;
                }
            }
            Err(e) => bail!("Error: {e}"),
        }
        Ok(())
    }

    fn cmd_delete(&self, key: &str, store: &mut crate::Store) -> Result<()> {
        if store.data_mut().delete(key) {
            secure_print(format!("{key} deleted"), self.insecure_stdout)?;
            self.save(store)?;
        } else {
            bail!("No such key '{key}' found");
        }
        Ok(())
    }

    /// `auth …` — multi-factor management. Subcommands: `auth policy {show|set
    /// EXPR}` and `auth factor {list|add password NAME|add fido2 NAME|remove
    /// NAME}`.
    fn cmd_auth(&self, line: &str, store: &mut crate::Store) -> Result<()> {
        let args = line.strip_prefix("auth").unwrap_or("").trim_start();
        let (sub, rest) = split_first_word(args);
        match sub {
            "policy" => self.cmd_auth_policy(rest, store),
            "factor" => self.cmd_auth_factor(rest, store),
            "" => {
                print_auth_help();
                Ok(())
            }
            other => bail!("unknown auth subcommand '{other}' (try: auth policy|factor)"),
        }
    }

    fn cmd_auth_policy(&self, args: &str, store: &mut crate::Store) -> Result<()> {
        let (verb, rest) = split_first_word(args);
        match verb {
            "" | "show" => {
                let expr = store.policy_expr();
                secure_print(expr, self.insecure_stdout)
            }
            "set" => {
                if rest.is_empty() {
                    bail!("syntax: auth policy set EXPR");
                }
                self.set_policy(rest, store)
            }
            other => bail!("unknown 'auth policy' subcommand '{other}' (try: show | set EXPR)"),
        }
    }

    fn cmd_auth_factor(&self, args: &str, store: &mut crate::Store) -> Result<()> {
        let (verb, rest) = split_first_word(args);
        match verb {
            "list" => self.list_factors(store),
            "add" => self.cmd_auth_factor_add(rest, store),
            "remove" => {
                let name =
                    first_word(rest).ok_or_else(|| anyhow!("syntax: auth factor remove NAME"))?;
                self.remove_factor(name, store)
            }
            "" => bail!("syntax: auth factor list|add|remove …"),
            other => {
                bail!("unknown 'auth factor' subcommand '{other}' (try: list | add | remove NAME)")
            }
        }
    }

    fn cmd_auth_factor_add(&self, args: &str, store: &mut crate::Store) -> Result<()> {
        let (kind, rest) = split_first_word(args);
        match kind {
            "password" => {
                let name = first_word(rest).ok_or_else(|| {
                    anyhow!("syntax: auth factor add password NAME (NAME is a label)")
                })?;
                self.enroll_password(name, store)
            }
            "fido2" => {
                let name = first_word(rest).ok_or_else(|| {
                    anyhow!("syntax: auth factor add fido2 NAME (NAME is a label)")
                })?;
                self.enroll_fido2(name, store)
            }
            _ => bail!("syntax: auth factor add password|fido2 NAME"),
        }
    }

    /// Enrols a FIDO2 security key as a new factor: registers an `hmac-secret`
    /// credential on the connected authenticator (touch, and a PIN if requested) and
    /// stores it. Like a password factor, it is unused until an `auth policy set`
    /// references it.
    #[cfg(feature = "fido2")]
    fn enroll_fido2(&self, name: &str, store: &mut crate::Store) -> Result<()> {
        secure_print(
            format!(
                "Enrolling FIDO2 factor '{name}'. The name is a label (shown by 'auth factor list' \
                 once unlocked; encrypted in the store) — not a secret."
            ),
            self.insecure_stdout,
        )?;
        // A PIN is usable only if one is set on the key — detect it rather than
        // asking, so we don't try (and fail) to use a PIN that isn't configured.
        let has_pin = rcypher::fido2::device_has_pin()?;
        let pin = if has_pin {
            Some(rcypher::cli::prompt_password("Security key PIN")?)
        } else {
            secure_print(
                "This key has no PIN set — the factor will unlock with a touch only. Set a PIN on \
                 the key (with your vendor's tool) if you want PIN protection."
                    .to_string(),
                self.insecure_stdout,
            )?;
            None
        };
        secure_print(
            "Touch your FIDO2 security key to enrol it…".to_string(),
            self.insecure_stdout,
        )?;
        let cred =
            rcypher::fido2::enroll(crate::cli::FIDO2_RP_ID, pin.as_ref().map(|p| p.as_str()))?;
        store.enroll_fido2(
            name,
            cred.credential_id,
            crate::cli::FIDO2_RP_ID.to_string(),
            cred.salt,
            has_pin,
            &cred.raw_hmac_secret,
        )?;
        self.save(store)?;
        secure_print(
            format!("Factor '{name}' enrolled. Reference it in 'auth policy set' to require it."),
            self.insecure_stdout,
        )?;
        Ok(())
    }

    /// Without FIDO2 support compiled in, enrollment is unavailable.
    #[cfg(not(feature = "fido2"))]
    #[allow(clippy::unused_self)]
    fn enroll_fido2(&self, _name: &str, _store: &mut crate::Store) -> Result<()> {
        bail!("this build has no FIDO2 support; rebuild rcypher-cli with --features fido2")
    }

    /// Lists the enrolled factors and their kinds.
    fn list_factors(&self, store: &crate::Store) -> Result<()> {
        for (name, kind) in store.factor_kinds() {
            let kind = match kind {
                FactorKind::Password { .. } => "password",
                FactorKind::Fido2 { .. } => "fido2",
            };
            secure_print(format!("{name} ({kind})"), self.insecure_stdout)?;
        }
        Ok(())
    }

    /// Adds a new password factor. `name` is a label, not the password; the password
    /// is prompted separately. The factor is unused by the policy until an `auth
    /// policy set` references it.
    fn enroll_password(&self, name: &str, store: &mut crate::Store) -> Result<()> {
        // Make the role of NAME explicit: it is a label, not the secret.
        // Catches the mix-up of typing a password where the factor name belongs.
        secure_print(
            format!(
                "Enrolling factor '{name}'. The name is a label (shown by 'auth factor list' once \
                 unlocked; encrypted in the store) — not the password; you'll enter the password next."
            ),
            self.insecure_stdout,
        )?;
        // The password is held in a zeroizing buffer, so every early return below
        // wipes it on drop; it is also wiped eagerly once the factor is enrolled.
        let mut password = prompt_new_password(&format!("factor '{name}'"))?;

        // Reject a password that resembles the name first, so that mix-up gets its
        // specific message rather than a generic strength warning.
        check_factor_password(name, &password)?;
        if !confirm_if_weak_password(&password, &[name, "rcypher"])? {
            bail!("enrollment cancelled (weak password not confirmed)");
        }

        store.enroll_password(name, &password)?;
        password.zeroize(); // wipe as soon as the factor's key material is derived

        self.save(store)?;
        secure_print(
            format!(
                "Factor '{name}' enrolled. It is not yet used by the policy — run \
                 'auth policy set EXPR' to require or accept it."
            ),
            self.insecure_stdout,
        )?;
        Ok(())
    }

    fn set_policy(&self, expr: &str, store: &mut crate::Store) -> Result<()> {
        store.set_policy(expr)?;
        let new_expr = store.policy_expr();
        self.save(store)?;
        secure_print(format!("Policy: {new_expr}"), self.insecure_stdout)?;
        Ok(())
    }

    /// Drops a factor (must not be referenced by the policy).
    fn remove_factor(&self, name: &str, store: &mut crate::Store) -> Result<()> {
        store.remove_factor(name)?;
        self.save(store)?;
        secure_print(format!("Factor '{name}' removed"), self.insecure_stdout)
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
    println!(
        "  auth factor add fido2 NAME    - Add a FIDO2 security-key factor (a hardware security key)"
    );
    println!("  auth factor remove NAME    - Remove a factor (not used by the policy)");
    println!("  auth policy show           - Show the current unlock policy");
    println!("  auth policy set EXPR       - Set the unlock policy, e.g. p1 or (p2 and fido2)");
}

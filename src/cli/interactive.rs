use crate::Cypher;
use crate::EncryptedValue;
use crate::Storage;
use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::STANDBY_TIMEOUT;
use crate::cli::completer::CypherCompleter;
use crate::cli::utils::{copy_to_clipboard, format_timestamp, secure_print};
use crate::is_debugger_attached;
use crate::load_storage;
use crate::save_storage;
use anyhow::{Result, bail};
use rustyline::CompletionType;
use rustyline::Config;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use zeroize::Zeroize;

pub struct InteractiveCli {
    prompt: String,
    insecure_stdout: bool,
    cypher: Cypher,
    filename: PathBuf,
}

impl InteractiveCli {
    pub const fn new(
        prompt: String,
        insecure_stdout: bool,
        cypher: Cypher,
        filename: PathBuf,
    ) -> Self {
        Self {
            prompt,
            insecure_stdout,
            cypher,
            filename,
        }
    }

    pub fn run(&self) -> Result<()> {
        let storage = Arc::new(Mutex::new(load_storage(&self.cypher, &self.filename)?));

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

        let mut last_use_time = SystemTime::now();

        rl.clear_screen()?;
        loop {
            // Check timeout
            if last_use_time
                .elapsed()
                .expect("time moves forward")
                .as_secs()
                > STANDBY_TIMEOUT
            {
                break;
            }
            if is_debugger_attached() {
                bail!("Debugger detected");
            }

            let readline = rl.readline(&self.prompt);
            match readline {
                Ok(mut input_line) => {
                    last_use_time = SystemTime::now();
                    let line = input_line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    rl.clear_screen()?;

                    let mut storage_guard = storage.lock().expect("able to lock");
                    if let Err(err) = self.process_cmd(line, &mut storage_guard) {
                        println!("{err}");
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

    fn process_cmd(&self, line: &str, storage: &mut Storage) -> Result<()> {
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
        let encrypted_value = EncryptedValue::encrypt(&self.cypher, value)?;
        storage.put(key.to_string(), encrypted_value);

        secure_print(format!("{key} stored"), self.insecure_stdout)?;

        save_storage(&self.cypher, storage, &self.filename)?;
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
                        )?;
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

    fn cmd_delete(&self, key: &str, storage: &mut Storage) -> Result<()> {
        if storage.delete(key) {
            secure_print(format!("{key} deleted"), self.insecure_stdout)?;
            save_storage(&self.cypher, storage, &self.filename)?;
        } else {
            bail!("No such key '{key}' found");
        }
        Ok(())
    }
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
}

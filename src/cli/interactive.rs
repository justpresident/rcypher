use crate::Cypher;
use crate::EncryptedValue;
use crate::StorageV5;
use crate::cli::CLIPBOARD_TTL_MS;
use crate::cli::STANDBY_TIMEOUT;
use crate::cli::completer::CypherCompleter;
use crate::cli::utils::{
    copy_to_clipboard, format_full_path, format_timestamp, parse_key_path, resolve_path,
    secure_print,
};
use crate::is_debugger_attached;
use crate::load_storage_v5;
use crate::save_storage_v5;
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
    current_path: Arc<Mutex<String>>,
}

impl InteractiveCli {
    pub fn new(prompt: String, insecure_stdout: bool, cypher: Cypher, filename: PathBuf) -> Self {
        Self {
            prompt,
            insecure_stdout,
            cypher,
            filename,
            current_path: Arc::new(Mutex::new(String::from("/"))),
        }
    }

    fn get_current_path(&self) -> String {
        let path = self.current_path.lock().expect("able to lock");
        if path.is_empty() {
            String::from("/")
        } else {
            path.clone()
        }
    }

    fn get_prompt(&self) -> String {
        let path = self.current_path.lock().expect("able to lock");
        self.prompt.replace("%p", path.as_ref())
    }

    pub fn run(&mut self) -> Result<()> {
        let storage = Arc::new(Mutex::new(load_storage_v5(&self.cypher, &self.filename)?));

        let config = Config::builder()
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .history_ignore_space(true)
            .history_ignore_dups(true)?
            .max_history_size(5)?
            .build();

        let completer = CypherCompleter::new(storage.clone(), self.current_path.clone());
        let mut rl = Editor::with_config(config)?;
        rl.set_helper(Some(completer));

        let mut last_use_time = SystemTime::now();

        rl.clear_screen()?;
        loop {
            if is_debugger_attached() {
                bail!("Debugger detected");
            }

            let prompt = self.get_prompt();
            let readline = rl.readline(&prompt);

            // Check timeout
            if last_use_time
                .elapsed()
                .expect("time moves forward")
                .as_secs()
                > STANDBY_TIMEOUT
            {
                break;
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
                        last_use_time = SystemTime::now();
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

    fn process_cmd(&self, line: &str, storage: &mut StorageV5) -> Result<()> {
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
            "mkdir" => {
                if parts.len() < 2 {
                    bail!("syntax: mkdir FOLDER_NAME");
                }
                self.cmd_mkdir(parts[1], storage)
            }
            "cd" => {
                let path = if parts.len() > 1 { parts[1] } else { "/" };
                self.cmd_cd(path, storage)
            }
            "pwd" => {
                self.cmd_pwd();
                Ok(())
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

    fn cmd_put(&self, key: &str, value: &str, storage: &mut StorageV5) -> Result<()> {
        let encrypted_value = EncryptedValue::encrypt(&self.cypher, value)?;
        let (folder_path, key_name) = parse_key_path(&self.get_current_path(), key);
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should go forward")
            .as_secs();
        storage.put_at_path(
            &folder_path,
            key_name.to_string(),
            encrypted_value,
            timestamp,
        );

        secure_print(format!("{key} stored"), self.insecure_stdout)?;

        save_storage_v5(&self.cypher, storage, &self.filename)?;
        Ok(())
    }

    fn cmd_get(&self, pattern: &str, storage: &StorageV5) -> Result<()> {
        let (folder_path, key_pattern) = parse_key_path(&self.get_current_path(), pattern);
        match storage.get_at_path(&folder_path, key_pattern, true) {
            // Recursive search
            Ok(results) => {
                let mut found = false;
                for (folder_path, key, val) in results {
                    found = true;
                    let mut secret = val.decrypt(&self.cypher)?;
                    let output = format!(
                        "{}: {}",
                        format_full_path(&folder_path, key, false),
                        &*secret
                    );
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

    fn cmd_copy(&self, key: &str, storage: &StorageV5) -> Result<()> {
        let current_path = self.get_current_path();
        match storage.get_at_path(&current_path, key, true) {
            Ok(mut results) => {
                let first = results.next();
                let second = results.next();

                match (first, second) {
                    (None, _) => bail!("No key '{key}' found!"),
                    (Some((first_path, first_key, _)), Some((second_path, second_key, _))) => {
                        // Multiple results - print all
                        println!("Multiple keys found! Plese specify exact key name:");
                        secure_print(
                            format_full_path(&first_path, first_key, false),
                            self.insecure_stdout,
                        )?;
                        secure_print(
                            format_full_path(&second_path, second_key, false),
                            self.insecure_stdout,
                        )?;
                        for (folder_path, key, _) in results {
                            secure_print(
                                format_full_path(&folder_path, key, false),
                                self.insecure_stdout,
                            )?;
                        }
                    }
                    (Some((_, _, val)), None) => {
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

    fn cmd_history(&self, key: &str, storage: &StorageV5) -> Result<()> {
        let (folder_path, key_name) = parse_key_path(&self.get_current_path(), key);
        if let Some(entries) = storage.history_at_path(&folder_path, key_name) {
            for entry in entries {
                let mut secret = entry.encrypted_value().decrypt(&self.cypher)?;
                let output = format!("[{}]: {}", format_timestamp(entry.timestamp), &*secret);
                secret.zeroize();
                secure_print(output, self.insecure_stdout)?;
            }
        } else {
            bail!("No key '{key}' found!");
        }
        Ok(())
    }

    fn cmd_search(&self, pattern: &str, storage: &StorageV5) -> Result<()> {
        let (folder_path, key_pattern) = parse_key_path(&self.get_current_path(), pattern);
        match storage.search_at_path(&folder_path, key_pattern, true) {
            // Recursive search
            Ok(keys) => {
                for (folder_path, key) in keys {
                    secure_print(
                        format_full_path(&folder_path, key, false),
                        self.insecure_stdout,
                    )?;
                }
            }
            Err(e) => bail!("Error: {e}"),
        }
        Ok(())
    }

    fn cmd_delete(&self, key: &str, storage: &mut StorageV5) -> Result<()> {
        let (folder_path, key_name) = parse_key_path(&self.get_current_path(), key);
        if storage.delete_at_path(&folder_path, key_name) {
            secure_print(format!("{key} deleted"), self.insecure_stdout)?;
            save_storage_v5(&self.cypher, storage, &self.filename)?;
        } else {
            bail!("No such key '{key}' found");
        }
        Ok(())
    }

    fn cmd_mkdir(&self, folder_name: &str, storage: &mut StorageV5) -> Result<()> {
        let (parent_path, new_folder_name) = parse_key_path(&self.get_current_path(), folder_name);
        storage.mkdir(&parent_path, new_folder_name)?;
        secure_print(
            format!("Folder '{folder_name}' created"),
            self.insecure_stdout,
        )?;
        save_storage_v5(&self.cypher, storage, &self.filename)?;
        Ok(())
    }

    fn cmd_cd(&self, path: &str, storage: &StorageV5) -> Result<()> {
        let current = self.get_current_path();
        let new_path = resolve_path(&current, path);

        // Verify the folder exists
        if storage.get_folder(&new_path).is_none() {
            bail!("Folder '{new_path}' not found");
        }

        *self.current_path.lock().expect("able to lock") = new_path;
        Ok(())
    }

    fn cmd_pwd(&self) {
        println!("{}", self.get_current_path());
    }
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // Clear screen
}

fn print_help() {
    println!("BASE COMMANDS:");
    println!("  put KEY VAL     - Store a key-value pair in current folder");
    println!("  get REGEXP      - Get values for keys matching regexp (recursive)");
    println!("  copy KEY        - Copy key value into system clipboard (recursive)");
    println!("  history KEY     - Show history of changes for a key in current folder");
    println!("  search REGEXP   - Search for keys matching regexp (recursive)");
    println!("  del|rm KEY      - Delete a key from current folder");
    println!();
    println!("FOLDER COMMANDS:");
    println!("  mkdir FOLDER    - Create a new folder in current directory");
    println!("  cd [PATH]       - Change to directory (use .. to go up, / for root)");
    println!("  pwd             - Print current working directory");
    println!();
    println!("OTHER:");
    println!("  help            - Show this help");
}

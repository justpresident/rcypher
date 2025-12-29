use std::sync::{Arc, Mutex};

use crate::StorageV5;
use crate::cli::utils::{format_full_path, parse_key_path};
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

pub struct CypherCompleter {
    storage: Arc<Mutex<StorageV5>>,
    current_path: Arc<Mutex<String>>,
}

impl CypherCompleter {
    pub const fn new(storage: Arc<Mutex<StorageV5>>, current_path: Arc<Mutex<String>>) -> Self {
        Self {
            storage,
            current_path,
        }
    }
}

impl Completer for CypherCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line = &line[..pos];
        let parts: Vec<&str> = line.split_whitespace().collect();

        // If we're at the beginning or just typed a command
        if parts.is_empty() || (parts.len() == 1 && !line.ends_with(' ')) {
            // Complete commands
            let commands = [
                "put", "get", "copy", "history", "search", "del", "rm", "mkdir", "cd", "pwd",
                "help",
            ];
            let prefix = parts.first().unwrap_or(&"");
            let matches: Vec<Pair> = commands
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: (*cmd).to_string(),
                    replacement: (*cmd).to_string(),
                })
                .collect();

            let start = pos - prefix.len();
            return Ok((start, matches));
        }

        // Complete arguments for commands
        if !parts.is_empty() {
            let cmd = parts[0];
            match cmd {
                "cd" | "mkdir" => {
                    // Complete with folder names
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let input = if parts.len() == 2 { parts[1] } else { "" };

                        let storage = self.storage.lock().expect("able to take a lock");
                        let current_path = self.current_path.lock().expect("able to lock");

                        // Parse input to get resolved path and prefix
                        let (target_path, prefix) = parse_key_path(&current_path, input);

                        // Extract original dir part to preserve user's input style in completions
                        // (e.g., if user typed "work/api", complete as "work/api_key", not "/work/api_key")
                        let dir_part = input.strip_suffix(prefix).unwrap_or("");

                        let mut matches: Vec<Pair> = Vec::new();
                        if let Some(folder) = storage.get_folder(&target_path) {
                            for name in folder.subfolders.keys() {
                                if name.starts_with(prefix) {
                                    let full_path = format_full_path(dir_part, name, true);
                                    matches.push(Pair {
                                        display: full_path.clone(),
                                        replacement: full_path,
                                    });
                                }
                            }
                        }
                        drop(current_path);
                        drop(storage);

                        matches.sort_by(|a, b| a.replacement.cmp(&b.replacement));

                        let start = pos - input.len();
                        return Ok((start, matches));
                    }
                }
                "get" | "history" | "del" | "rm" | "put" | "copy" | "search" => {
                    // Complete with keys and folders from current directory
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let input = if parts.len() == 2 { parts[1] } else { "" };

                        let storage = self.storage.lock().expect("able to take a lock");
                        let current_path = self.current_path.lock().expect("able to lock");

                        // Parse input to get resolved path and prefix
                        let (target_path, prefix) = parse_key_path(&current_path, input);

                        // Extract original dir part to preserve user's input style in completions
                        // (e.g., if user typed "work/api", complete as "work/api_key", not "/work/api_key")
                        let dir_part = input.strip_suffix(prefix).unwrap_or("");

                        let mut matches: Vec<Pair> = Vec::new();
                        if let Some(folder) = storage.get_folder(&target_path) {
                            // Add matching secret keys
                            for key in folder.secrets.keys() {
                                if key.starts_with(prefix) {
                                    let full_path = format_full_path(dir_part, key, false);
                                    matches.push(Pair {
                                        display: full_path.clone(),
                                        replacement: full_path,
                                    });
                                }
                            }
                            // Add matching folder names
                            for name in folder.subfolders.keys() {
                                if name.starts_with(prefix) {
                                    let full_path = format_full_path(dir_part, name, true);
                                    matches.push(Pair {
                                        display: full_path.clone(),
                                        replacement: full_path,
                                    });
                                }
                            }
                        }
                        drop(current_path);
                        drop(storage);

                        matches.sort_by(|a, b| a.replacement.cmp(&b.replacement));

                        let start = pos - input.len();
                        return Ok((start, matches));
                    }
                }
                _ => {}
            }
        }

        Ok((pos, vec![]))
    }
}

impl Hinter for CypherCompleter {
    type Hint = String;
}

impl Highlighter for CypherCompleter {}

impl Validator for CypherCompleter {}

impl Helper for CypherCompleter {}

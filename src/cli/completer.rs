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

    /// Helper function to complete paths with optional keys and/or folders
    fn complete_path(
        &self,
        input: &str,
        pos: usize,
        include_keys: bool,
        include_folders: bool,
    ) -> (usize, Vec<Pair>) {
        let storage = self.storage.lock().expect("able to take a lock");
        let current_path = self.current_path.lock().expect("able to lock");

        // Parse input to get resolved path and prefix
        let (target_path, prefix) = parse_key_path(&current_path, input);

        // Extract original dir part to preserve user's input style in completions
        let dir_part = input.strip_suffix(prefix).unwrap_or("");

        let mut matches: Vec<Pair> = Vec::new();
        if let Some(folder) = storage.get_folder(&target_path) {
            // Iterate through all items in the folder
            for (name, item) in &folder.items {
                if !name.starts_with(prefix) {
                    continue;
                }

                // Check if we should include this item based on its type
                let should_include = match item {
                    _ if item.is_secret() => include_keys,
                    _ if item.is_navigable() || item.is_locked() => include_folders,
                    _ => false,
                };

                if should_include {
                    let is_folder = item.is_any_folder();
                    let full_path = format_full_path(dir_part, name, is_folder);
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
        (start, matches)
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
                "put", "get", "copy", "history", "search", "del", "rm", "mkdir", "cd", "pwd", "mv",
                "move", "help",
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
                    // Complete with folder names only
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let input = if parts.len() == 2 { parts[1] } else { "" };
                        return Ok(self.complete_path(input, pos, false, true));
                    }
                }
                "get" | "history" | "del" | "rm" | "put" | "copy" | "search" => {
                    // Complete with keys and folders
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let input = if parts.len() == 2 { parts[1] } else { "" };
                        return Ok(self.complete_path(input, pos, true, true));
                    }
                }
                "mv" | "move" => {
                    // First argument: complete with keys and folders (source)
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let input = if parts.len() == 2 { parts[1] } else { "" };
                        return Ok(self.complete_path(input, pos, true, true));
                    }
                    // Second argument: complete with folders only (destination)
                    else if parts.len() == 2 || (parts.len() == 3 && !line.ends_with(' ')) {
                        let input = if parts.len() == 3 { parts[2] } else { "" };
                        return Ok(self.complete_path(input, pos, false, true));
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

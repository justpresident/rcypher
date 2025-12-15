use std::sync::{Arc, Mutex};

use crate::Storage;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

pub(crate) struct CypherCompleter {
    storage: Arc<Mutex<Storage>>,
}

impl CypherCompleter {
    pub fn new(storage: Arc<Mutex<Storage>>) -> Self {
        CypherCompleter { storage }
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
                "put", "get", "copy", "history", "search", "del", "rm", "help",
            ];
            let prefix = parts.first().unwrap_or(&"");
            let matches: Vec<Pair> = commands
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();

            let start = pos - prefix.len();
            return Ok((start, matches));
        }

        // Complete keys for commands that need them
        if !parts.is_empty() {
            let cmd = parts[0];
            match cmd {
                "get" | "history" | "del" | "rm" | "put" | "copy" | "search" => {
                    // Only complete if we have exactly 1 argument (the command itself)
                    // or 2 arguments where the second is incomplete
                    if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) {
                        let prefix = if parts.len() == 2 { parts[1] } else { "" };

                        let storage = self.storage.lock().unwrap();
                        let mut keys: Vec<String> = storage.data.keys().cloned().collect();
                        keys.sort();

                        let matches: Vec<Pair> = keys
                            .iter()
                            .filter(|key| key.starts_with(prefix))
                            .map(|key| Pair {
                                display: key.clone(),
                                replacement: key.clone(),
                            })
                            .collect();

                        let start = pos - prefix.len();
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

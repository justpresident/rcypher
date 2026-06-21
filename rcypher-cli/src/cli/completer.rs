use std::sync::{Arc, Mutex};

use rcypher::Storage;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

/// Top-level interactive commands, in display order.
const COMMANDS: &[&str] = &[
    "put", "get", "copy", "history", "search", "del", "rm", "enroll", "factors", "policy",
    "remove", "help",
];

/// Commands whose argument is a store key (and so completes from the store).
const KEY_COMMANDS: &[&str] = &["get", "history", "del", "rm", "put", "copy", "search"];

/// The fixed keyword arguments of the multi-factor auth commands.
fn subcommands_of(command: &str) -> &'static [&'static str] {
    match command {
        "enroll" => &["password", "yubikey"],
        "policy" => &["show", "set"],
        "remove" => &["factor"],
        _ => &[],
    }
}

/// Pure completion logic: given the input up to the cursor and the known store
/// keys, returns the replacement start position and the candidate strings. Kept
/// free of rustyline's `Context` (which the completer ignores) so it is unit
/// testable.
fn candidates(line: &str, pos: usize, keys: &[String]) -> (usize, Vec<String>) {
    let line = &line[..pos];
    let parts: Vec<&str> = line.split_whitespace().collect();
    let typing_first_word = parts.len() <= 1 && !line.ends_with(' ');
    // Whether we're on the second token (the command's first argument).
    let on_arg = parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' '));
    let arg_prefix = if parts.len() == 2 { parts[1] } else { "" };

    // Completing the command itself.
    if parts.is_empty() || typing_first_word {
        let prefix = parts.first().copied().unwrap_or("");
        let matches = COMMANDS
            .iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .map(|cmd| (*cmd).to_string())
            .collect();
        return (pos - prefix.len(), matches);
    }

    // Completing an auth command's keyword argument (e.g. `policy ` → show/set).
    let subcommands = subcommands_of(parts[0]);
    if !subcommands.is_empty() && on_arg {
        let matches = subcommands
            .iter()
            .filter(|sub| sub.starts_with(arg_prefix))
            .map(|sub| (*sub).to_string())
            .collect();
        return (pos - arg_prefix.len(), matches);
    }

    // Completing a store key for the commands that take one.
    if KEY_COMMANDS.contains(&parts[0]) && on_arg {
        let mut matches: Vec<String> = keys
            .iter()
            .filter(|key| key.starts_with(arg_prefix))
            .cloned()
            .collect();
        matches.sort();
        return (pos - arg_prefix.len(), matches);
    }

    (pos, vec![])
}

pub struct CypherCompleter {
    storage: Arc<Mutex<Storage>>,
}

impl CypherCompleter {
    pub const fn new(storage: Arc<Mutex<Storage>>) -> Self {
        Self { storage }
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
        let keys: Vec<String> = {
            let storage = self.storage.lock().expect("able to take a lock");
            storage.data.keys().cloned().collect()
        };

        let (start, cands) = candidates(line, pos, &keys);
        let pairs = cands
            .into_iter()
            .map(|c| Pair {
                display: c.clone(),
                replacement: c,
            })
            .collect();
        Ok((start, pairs))
    }
}

impl Hinter for CypherCompleter {
    type Hint = String;
}

impl Highlighter for CypherCompleter {}

impl Validator for CypherCompleter {}

impl Helper for CypherCompleter {}

#[cfg(test)]
mod tests {
    use super::candidates;

    /// Candidate strings for `line` with the cursor at its end, against a small
    /// fixed set of store keys.
    fn complete(line: &str) -> Vec<String> {
        let keys = ["alpha".to_string(), "beta".to_string()];
        candidates(line, line.len(), &keys).1
    }

    #[test]
    fn top_level_includes_auth_commands() {
        let all = complete("");
        for cmd in [
            "put", "get", "copy", "history", "search", "del", "rm", "enroll", "factors", "policy",
            "remove", "help",
        ] {
            assert!(all.contains(&cmd.to_string()), "missing '{cmd}' in {all:?}");
        }
    }

    #[test]
    fn completes_command_prefix() {
        assert_eq!(complete("po"), vec!["policy".to_string()]);
        assert_eq!(complete("fa"), vec!["factors".to_string()]);
        assert_eq!(complete("en"), vec!["enroll".to_string()]);
    }

    #[test]
    fn completes_auth_subcommands() {
        assert_eq!(
            complete("enroll "),
            vec!["password".to_string(), "yubikey".to_string()]
        );
        assert_eq!(complete("enroll p"), vec!["password".to_string()]);
        assert_eq!(
            complete("policy "),
            vec!["show".to_string(), "set".to_string()]
        );
        assert_eq!(complete("remove "), vec!["factor".to_string()]);
    }

    #[test]
    fn completes_store_keys_for_key_commands() {
        assert_eq!(
            complete("get "),
            vec!["alpha".to_string(), "beta".to_string()]
        );
        assert_eq!(complete("get a"), vec!["alpha".to_string()]);
    }

    #[test]
    fn no_completion_for_argless_or_unknown_positions() {
        assert!(complete("factors ").is_empty());
        assert!(complete("enroll password ").is_empty());
    }
}

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
    "remove", "upgrade", "help",
];

/// Commands whose argument is a store key (and so completes from the store).
const KEY_COMMANDS: &[&str] = &["get", "history", "del", "rm", "put", "copy", "search"];

/// Boolean operators allowed in a `policy set` expression.
const OPERATORS: &[&str] = &["and", "or"];

/// The fixed keyword arguments of the multi-factor auth commands.
fn subcommands_of(command: &str) -> &'static [&'static str] {
    match command {
        "enroll" => &["password", "yubikey"],
        "policy" => &["show", "set"],
        "remove" => &["factor"],
        _ => &[],
    }
}

/// The trailing run of factor-name characters (`[A-Za-z0-9_-]`) at the end of
/// `line` — the partial token being completed inside a policy expression, even
/// when it directly follows a `(`.
fn trailing_ident(line: &str) -> &str {
    let start = line
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_alphanumeric() || *c == '-' || *c == '_')
        .last()
        .map_or(line.len(), |(i, _)| i);
    &line[start..]
}

fn matching(options: &[&str], prefix: &str) -> Vec<String> {
    options
        .iter()
        .filter(|opt| opt.starts_with(prefix))
        .map(|opt| (*opt).to_string())
        .collect()
}

fn matching_sorted(options: &[String], prefix: &str) -> Vec<String> {
    let mut matches: Vec<String> = options
        .iter()
        .filter(|opt| opt.starts_with(prefix))
        .cloned()
        .collect();
    matches.sort();
    matches
}

/// Pure completion logic: given the input up to the cursor, the known store
/// keys, and the enrolled factor ids, returns the replacement start position and
/// the candidate strings. Kept free of rustyline's `Context` (which the completer
/// ignores) so it is unit testable.
fn candidates(line: &str, pos: usize, keys: &[String], factors: &[String]) -> (usize, Vec<String>) {
    let line = &line[..pos];
    let parts: Vec<&str> = line.split_whitespace().collect();
    let ends_with_space = line.ends_with(' ');
    // Whether we're on the second token (the command's first argument).
    let on_arg = parts.len() == 1 || (parts.len() == 2 && !ends_with_space);
    let arg_prefix = if parts.len() == 2 { parts[1] } else { "" };

    // 1. Completing the command itself.
    if parts.is_empty() || (parts.len() == 1 && !ends_with_space) {
        let prefix = parts.first().copied().unwrap_or("");
        return (pos - prefix.len(), matching(COMMANDS, prefix));
    }

    // 2. `policy set EXPR` — complete factor names and the and/or operators
    //    anywhere in the expression (the prefix is the trailing identifier, so it
    //    works right after a `(` too).
    if parts[0] == "policy" && parts.get(1).copied() == Some("set") && !on_arg {
        let prefix = trailing_ident(line);
        let mut matches = matching_sorted(factors, prefix);
        matches.extend(matching(OPERATORS, prefix));
        return (pos - prefix.len(), matches);
    }

    // 3. Completing an auth command's keyword argument (e.g. `policy ` → show/set).
    let subcommands = subcommands_of(parts[0]);
    if !subcommands.is_empty() && on_arg {
        return (pos - arg_prefix.len(), matching(subcommands, arg_prefix));
    }

    // 4. `remove factor NAME` — complete factor names.
    if parts[0] == "remove" && parts.get(1).copied() == Some("factor") {
        let on_name =
            (parts.len() == 2 && ends_with_space) || (parts.len() == 3 && !ends_with_space);
        if on_name {
            let prefix = if parts.len() == 3 { parts[2] } else { "" };
            return (pos - prefix.len(), matching_sorted(factors, prefix));
        }
    }

    // 5. Completing a store key for the commands that take one.
    if KEY_COMMANDS.contains(&parts[0]) && on_arg {
        return (pos - arg_prefix.len(), matching_sorted(keys, arg_prefix));
    }

    (pos, vec![])
}

pub struct CypherCompleter {
    storage: Arc<Mutex<Storage>>,
    /// The currently enrolled factor ids, shared with the interactive session so
    /// `enroll`/`remove` keep completion in sync.
    factors: Arc<Mutex<Vec<String>>>,
}

impl CypherCompleter {
    pub const fn new(storage: Arc<Mutex<Storage>>, factors: Arc<Mutex<Vec<String>>>) -> Self {
        Self { storage, factors }
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
        let factors = self.factors.lock().expect("able to take a lock").clone();

        let (start, cands) = candidates(line, pos, &keys, &factors);
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
    /// fixed set of store keys and factor ids.
    fn complete(line: &str) -> Vec<String> {
        let keys = ["alpha".to_string(), "beta".to_string()];
        let factors = ["primary".to_string(), "backup".to_string()];
        candidates(line, line.len(), &keys, &factors).1
    }

    #[test]
    fn top_level_includes_auth_commands() {
        let all = complete("");
        for cmd in [
            "put", "get", "copy", "history", "search", "del", "rm", "enroll", "factors", "policy",
            "remove", "upgrade", "help",
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
    fn completes_factor_names_for_remove_factor() {
        assert_eq!(
            complete("remove factor "),
            vec!["backup".to_string(), "primary".to_string()]
        );
        assert_eq!(complete("remove factor p"), vec!["primary".to_string()]);
    }

    #[test]
    fn completes_factors_and_operators_in_policy_set() {
        assert_eq!(
            complete("policy set "),
            vec![
                "backup".to_string(),
                "primary".to_string(),
                "and".to_string(),
                "or".to_string(),
            ]
        );
        assert_eq!(complete("policy set pr"), vec!["primary".to_string()]);
        assert_eq!(complete("policy set primary o"), vec!["or".to_string()]);
        // The prefix is the trailing identifier, so completion works after a `(`.
        assert_eq!(complete("policy set (ba"), vec!["backup".to_string()]);
    }

    #[test]
    fn no_completion_for_argless_or_unknown_positions() {
        assert!(complete("factors ").is_empty());
        assert!(complete("enroll password ").is_empty());
    }
}

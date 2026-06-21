use std::sync::{Arc, Mutex};

use rcypher::Storage;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

/// Top-level interactive commands, in display order.
const TOP_COMMANDS: &[&str] = &[
    "put", "get", "copy", "history", "search", "del", "rm", "auth", "help",
];

/// Commands whose argument is a store key (and so completes from the store).
const KEY_COMMANDS: &[&str] = &["get", "history", "del", "rm", "put", "copy", "search"];

/// Boolean operators allowed in an `auth policy set` expression.
const OPERATORS: &[&str] = &["and", "or"];

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
    let words: Vec<&str> = line.split_whitespace().collect();
    let ends_with_space = line.ends_with(' ');

    // The index of the token being completed and its prefix.
    let (idx, prefix) = if ends_with_space || words.is_empty() {
        (words.len(), "")
    } else {
        (words.len() - 1, words[words.len() - 1])
    };
    let fixed = |opts: &[&str]| (pos - prefix.len(), matching(opts, prefix));

    // The command word itself.
    if idx == 0 {
        return fixed(TOP_COMMANDS);
    }

    // `auth policy set EXPR`: factor names and and/or operators, anywhere in the
    // expression (the prefix is the trailing identifier, so it works after a `(`).
    if words.first() == Some(&"auth")
        && words.get(1) == Some(&"policy")
        && words.get(2) == Some(&"set")
        && idx >= 3
    {
        let ident = trailing_ident(line);
        let mut matches = matching_sorted(factors, ident);
        matches.extend(matching(OPERATORS, ident));
        return (pos - ident.len(), matches);
    }

    match words.first().copied() {
        Some("auth") => match (idx, words.get(1).copied(), words.get(2).copied()) {
            (1, _, _) => fixed(&["policy", "factor", "upgrade"]),
            (2, Some("policy"), _) => fixed(&["show", "set"]),
            (2, Some("factor"), _) => fixed(&["list", "add", "remove"]),
            (3, Some("factor"), Some("add")) => fixed(&["password", "yubikey"]),
            (3, Some("factor"), Some("remove")) => {
                (pos - prefix.len(), matching_sorted(factors, prefix))
            }
            _ => (pos, vec![]),
        },
        Some(cmd) if KEY_COMMANDS.contains(&cmd) && idx == 1 => {
            (pos - prefix.len(), matching_sorted(keys, prefix))
        }
        _ => (pos, vec![]),
    }
}

pub struct CypherCompleter {
    storage: Arc<Mutex<Storage>>,
    /// The currently enrolled factor ids, shared with the interactive session so
    /// `auth factor add`/`remove` keep completion in sync.
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
    fn top_level_commands() {
        let all = complete("");
        for cmd in [
            "put", "get", "copy", "history", "search", "del", "rm", "auth", "help",
        ] {
            assert!(all.contains(&cmd.to_string()), "missing '{cmd}' in {all:?}");
        }
        // The old flat auth commands are no longer top-level.
        for gone in ["enroll", "factors", "policy", "remove", "upgrade"] {
            assert!(
                !all.contains(&gone.to_string()),
                "stale '{gone}' in {all:?}"
            );
        }
    }

    #[test]
    fn completes_command_prefix() {
        assert_eq!(complete("au"), vec!["auth".to_string()]);
        assert_eq!(complete("ge"), vec!["get".to_string()]);
    }

    #[test]
    fn completes_auth_subsystems() {
        assert_eq!(
            complete("auth "),
            vec![
                "policy".to_string(),
                "factor".to_string(),
                "upgrade".to_string()
            ]
        );
        assert_eq!(complete("auth p"), vec!["policy".to_string()]);
    }

    #[test]
    fn completes_auth_policy_and_factor_verbs() {
        assert_eq!(
            complete("auth policy "),
            vec!["show".to_string(), "set".to_string()]
        );
        assert_eq!(
            complete("auth factor "),
            vec!["list".to_string(), "add".to_string(), "remove".to_string()]
        );
        assert_eq!(
            complete("auth factor add "),
            vec!["password".to_string(), "yubikey".to_string()]
        );
    }

    #[test]
    fn completes_factor_names_for_remove() {
        assert_eq!(
            complete("auth factor remove "),
            vec!["backup".to_string(), "primary".to_string()]
        );
        assert_eq!(
            complete("auth factor remove p"),
            vec!["primary".to_string()]
        );
    }

    #[test]
    fn completes_factors_and_operators_in_policy_set() {
        assert_eq!(
            complete("auth policy set "),
            vec![
                "backup".to_string(),
                "primary".to_string(),
                "and".to_string(),
                "or".to_string(),
            ]
        );
        assert_eq!(complete("auth policy set pr"), vec!["primary".to_string()]);
        assert_eq!(
            complete("auth policy set primary o"),
            vec!["or".to_string()]
        );
        // The prefix is the trailing identifier, so completion works after a `(`.
        assert_eq!(complete("auth policy set (ba"), vec!["backup".to_string()]);
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
        assert!(complete("help ").is_empty());
        assert!(complete("auth upgrade ").is_empty());
        assert!(complete("auth factor add password ").is_empty());
    }
}

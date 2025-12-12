use anyhow::Result;
use clap::{ArgGroup, Parser};
use rcypher::*; // Import from lib
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Editor, Helper};
use std::io::{self};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use zeroize::Zeroize;

const STANDBY_TIMEOUT: u64 = 300;

#[derive(Parser)]
#[command(group(
    ArgGroup::new("mode")
        .args(&["encrypt", "decrypt"])
        .multiple(false)
))]
#[command(name = "cypher")]
#[command(about = "Command line cypher tool for encrypted key-value storage")]
struct Cli {
    #[arg(short, long, action)]
    encrypt: bool,
    #[arg(short, long, action)]
    decrypt: bool,

    // This is only for automated testing
    #[arg(long, hide(true))]
    password: Option<String>,

    #[arg(long, default_value = "cypher > ")]
    prompt: String,

    /// File to encrypt/decrypt or use as storage
    filename: PathBuf,
}

struct CypherCompleter {
    storage: Arc<Mutex<Storage>>,
}

impl CypherCompleter {
    fn new(storage: Arc<Mutex<Storage>>) -> Self {
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
            let commands = ["put", "get", "history", "search", "del", "rm", "help"];
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
                "get" | "history" | "del" | "rm" | "put" | "search" => {
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

fn run_interactive(mut password: String, filename: PathBuf, prompt: String) -> Result<()> {
    let storage = Arc::new(Mutex::new(load_storage(&password, &filename)?));

    let config = Config::builder()
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .history_ignore_space(true)
        .history_ignore_dups(true)?
        .max_history_size(1000)?
        .build();

    let completer = CypherCompleter::new(Arc::clone(&storage));
    let mut rl = Editor::with_config(config)?;
    rl.set_helper(Some(completer));

    let key = Cypher::encryption_key_for_file(&password, &filename)?;
    Zeroize::zeroize(&mut password);

    let cypher = Cypher::new(key);

    let start_time = SystemTime::now();

    loop {
        // Check timeout
        if start_time.elapsed().unwrap().as_secs() > STANDBY_TIMEOUT {
            break;
        }

        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                let cmd = parts[0];

                let mut storage_guard = storage.lock().unwrap();

                match cmd {
                    "put" => {
                        if parts.len() < 3 {
                            println!("syntax: put KEY VAL");
                            continue;
                        }
                        storage_guard.put(parts[1].to_string(), parts[2].to_string());
                        println!("{} stored", parts[1]);
                        save_storage(&cypher, &storage_guard, &filename)?;
                    }
                    "get" => {
                        if parts.len() < 2 {
                            println!("syntax: get REGEXP");
                            continue;
                        }
                        match storage_guard.get(parts[1]) {
                            Ok(results) => {
                                if results.is_empty() {
                                    println!("No keys matching '{}' found!", parts[1]);
                                } else {
                                    for (key, val) in results {
                                        println!("{}: {}", key, val);
                                    }
                                }
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    "history" => {
                        if parts.len() < 2 {
                            println!("syntax: history KEY");
                            continue;
                        }
                        if let Some(entries) = storage_guard.history(parts[1]) {
                            for entry in entries {
                                println!(
                                    "[{}]: {}",
                                    format_timestamp(entry.timestamp),
                                    entry.value
                                );
                            }
                        } else {
                            println!("No key '{}' found!", parts[1]);
                        }
                    }
                    "search" => {
                        let pattern = if parts.len() > 1 { parts[1] } else { "" };
                        match storage_guard.search(pattern) {
                            Ok(keys) => {
                                for key in keys {
                                    println!("{}", key);
                                }
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    "del" | "rm" => {
                        if parts.len() < 2 {
                            println!("syntax: del KEY");
                            continue;
                        }
                        if storage_guard.delete(parts[1]) {
                            println!("{} deleted", parts[1]);
                            save_storage(&cypher, &storage_guard, &filename)?;
                        } else {
                            println!("No such key '{}' found", parts[1]);
                        }
                    }
                    "help" => {
                        drop(storage_guard);
                        print_help();
                    }
                    _ => {
                        println!("No such command '{}'\n", cmd);
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    print!("\x1B[2J\x1B[1;1H"); // Clear screen
    Ok(())
}

fn print_help() {
    println!("USER COMMANDS:");
    println!("  put KEY VAL     - Store a key-value pair");
    println!("  get REGEXP      - Get values for keys matching regexp");
    println!("  history KEY     - Show history of changes for a key");
    println!("  search REGEXP   - Search for keys matching regexp");
    println!("  del|rm KEY      - Delete a key");
    println!("  help            - Show this help");
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut password = match cli.password {
        Some(passwd) => passwd.clone(),
        None => {
            rpassword::prompt_password(format!("Enter Password for {}: ", cli.filename.display()))?
        }
    };

    if cli.encrypt {
        let key = EncryptionKey::from_password(CypherVersion::V7WithKdf, &password)?;
        Zeroize::zeroize(&mut password);
        let cypher = Cypher::new(key);

        cypher.encrypt_file(&cli.filename, &mut io::stdout())?;
    } else if cli.decrypt {
        let key = Cypher::encryption_key_for_file(&password, &cli.filename)?;
        Zeroize::zeroize(&mut password);

        let cypher = Cypher::new(key);

        cypher.decrypt_file(&cli.filename, &mut io::stdout())?;
    } else {
        run_interactive(password, cli.filename, cli.prompt)?;
    }

    Ok(())
}

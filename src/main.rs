use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use nix::fcntl::{Flock, FlockArg};
use rcypher::*; // Import from lib
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Editor, Helper};
use std::fs::OpenOptions;
use std::io::{self, Write as _};
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
#[command(about = "Command line cypher tool for encrypting secrets.
By default treats provided filename as an encrypted key-value storage and provides put/get functionality for individual secrets.
In this mode, the file is created if it doesn't exist.
Otherwise, with --encrypt and --decrypt parameters it allows encryption of any other type of file.
")]
struct CliParams {
    /// Encrypt a full file
    #[arg(short, long, action)]
    encrypt: bool,
    /// Decrypt a full file
    #[arg(short, long, action)]
    decrypt: bool,

    /// Don't prompt for password, use provided as a parameeter.
    /// This is only for automated testing
    #[arg(long, hide(true))]
    insecure_password: Option<String>,

    /// Use stdout to output secrets.
    /// This is only for automated testing
    #[arg(long, action, default_value_t = false, hide(true))]
    insecure_stdout: bool,

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

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H"); // Clear screen
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

struct InteractiveCli {
    // Use insecure prints to stdout
    insecure_stdout: bool,
}

impl InteractiveCli {
    // Prints directly to tty to avoid
    // - snooping passwords from process stdout
    // - lingering passwords in memory
    fn secure_print(&self, what: impl AsRef<str>) -> Result<()> {
        if self.insecure_stdout {
            println!("{}", what.as_ref());
            return Ok(());
        }
        let tty = OpenOptions::new().write(true).open("/dev/tty")?;
        let mut lock = match Flock::lock(tty, FlockArg::LockExclusive) {
            Ok(l) => l,
            Err((_, e)) => bail!(e),
        };
        lock.write_all(what.as_ref().as_bytes())?;
        lock.write_all(b"\n")?;
        lock.flush()?;
        Ok(())
    }
    pub fn run(&self, cypher: &Cypher, filename: PathBuf, prompt: String) -> Result<()> {
        let storage = Arc::new(Mutex::new(load_storage(cypher, &filename)?));

        let config = Config::builder()
            .completion_type(CompletionType::List)
            .auto_add_history(true)
            .history_ignore_space(true)
            .history_ignore_dups(true)?
            .max_history_size(5)?
            .build();

        let completer = CypherCompleter::new(Arc::clone(&storage));
        let mut rl = Editor::with_config(config)?;
        rl.set_helper(Some(completer));

        let start_time = SystemTime::now();

        rl.clear_screen()?;
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
                            rl.clear_screen()?;
                            if parts.len() < 3 {
                                println!("syntax: put KEY VAL");
                                continue;
                            }
                            storage_guard.put(parts[1].to_string(), parts[2].to_string());
                            self.secure_print(format!("{} stored", parts[1]))?;
                            save_storage(&cypher, &storage_guard, &filename)?;
                        }
                        "get" => {
                            rl.clear_screen()?;
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
                                            self.secure_print(format!("{}: {}", key, val))?;
                                        }
                                    }
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                        "history" => {
                            rl.clear_screen()?;
                            if parts.len() < 2 {
                                println!("syntax: history KEY");
                                continue;
                            }
                            if let Some(entries) = storage_guard.history(parts[1]) {
                                for entry in entries {
                                    self.secure_print(format!(
                                        "[{}]: {}",
                                        format_timestamp(entry.timestamp),
                                        entry.value
                                    ))?;
                                }
                            } else {
                                println!("No key '{}' found!", parts[1]);
                            }
                        }
                        "search" => {
                            rl.clear_screen()?;
                            let pattern = if parts.len() > 1 { parts[1] } else { "" };
                            match storage_guard.search(pattern) {
                                Ok(keys) => {
                                    for key in keys {
                                        self.secure_print(key)?;
                                    }
                                }
                                Err(e) => println!("Error: {}", e),
                            }
                        }
                        "del" | "rm" => {
                            rl.clear_screen()?;
                            if parts.len() < 2 {
                                println!("syntax: del KEY");
                                continue;
                            }
                            if storage_guard.delete(parts[1]) {
                                self.secure_print(format!("{} deleted", parts[1]))?;
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

        clear_screen();
        Ok(())
    }
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
    let params = CliParams::parse();

    let mut password = match params.insecure_password {
        Some(passwd) => passwd.clone(),
        None => rpassword::prompt_password(format!(
            "Enter Password for {}: ",
            params.filename.display()
        ))?,
    };

    if params.encrypt {
        let key = EncryptionKey::from_password(CypherVersion::V7WithKdf, &password)?;
        Zeroize::zeroize(&mut password);
        let cypher = Cypher::new(key);

        cypher.encrypt_file(&params.filename, &mut io::stdout())?;
    } else if params.decrypt {
        let key = Cypher::encryption_key_for_file(&password, &params.filename)?;
        Zeroize::zeroize(&mut password);

        let cypher = Cypher::new(key);

        cypher.decrypt_file(&params.filename, &mut io::stdout())?;
    } else {
        let interactive_cli = InteractiveCli {
            insecure_stdout: params.insecure_stdout,
        };
        let key = Cypher::encryption_key_for_file(&password, &params.filename)?;
        Zeroize::zeroize(&mut password);

        let cypher = Cypher::new(key);

        interactive_cli.run(&cypher, params.filename, params.prompt)?;
    }

    Ok(())
}

#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::panic,
    clippy::dbg_macro,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::redundant_pub_crate
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::multiple_crate_versions,
    clippy::missing_panics_doc,
    clippy::option_if_let_else
)]

use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use nix::fcntl::{Flock, FlockArg};
use rcypher::cli::utils::get_password;
use rcypher::{
    Argon2Params, Cypher, CypherVersion, EncryptedValue, EncryptionKey, Spinner, StorageV5,
    ThreadStopGuard, load_storage_v5, save_storage_v5,
}; // Import from lib
use rcypher::{cli, disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

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
#[allow(clippy::struct_excessive_bools)]
struct CliParams {
    /// Encrypt a full file
    #[arg(short, long, action)]
    encrypt: bool,
    /// Decrypt a full file
    #[arg(short, long, action)]
    decrypt: bool,

    /// Output file for encypt/decrypt operation.
    /// If not specified, output will go to stdout
    #[arg(short, long, default_value = "-")]
    output: String,

    /// Don't prompt for password, use the one provided in a parameter.
    /// This is only for automated testing
    #[arg(long, hide(true))]
    insecure_password: Option<String>,

    /// Use stdout to output secrets.
    /// This is only for automated testing
    #[arg(long, action, default_value_t = false, hide(true))]
    insecure_stdout: bool,

    /// Allow debuggers to attach (disables ptrace protection).
    /// This is only for automated testing
    #[arg(long, action, default_value_t = false, hide(true))]
    insecure_allow_debugging: bool,

    /// Don't show loading animation during startup and warnings
    #[arg(long, action, default_value_t = false, hide(true))]
    quiet: bool,

    /// Prompt for interactive mode.
    /// %p is replaced with the current folder path
    #[arg(long, default_value = "cypher : %p > ")]
    prompt: String,

    /// Upgrade file with stored secrets to the latest supported encryption format. The file will
    /// be updated in place
    #[arg(short, long, action)]
    upgrade_storage: bool,

    /// Update storage with entries from another encrypted storage file (e.g., Dropbox conflict copy).
    /// Entries with newer timestamps will be merged into the main file
    #[arg(long)]
    update_with: Option<PathBuf>,

    /// File to encrypt/decrypt or use as storage
    filename: PathBuf,
}

fn run_encrypt(params: &CliParams, key: EncryptionKey) -> Result<()> {
    let cypher = Cypher::new(key);

    if params.output == "-" {
        cypher.encrypt_file(&params.filename, &mut io::stdout())?;
    } else {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&params.output)?;
        let mut lock = match Flock::lock(file, FlockArg::LockExclusive) {
            Ok(l) => l,
            Err((_, e)) => bail!(e),
        };
        cypher.encrypt_file(&params.filename, &mut *lock)?;
        lock.flush()?;
    }
    Ok(())
}

fn run_decrypt(params: &CliParams, key: EncryptionKey) -> Result<()> {
    if key.version < CypherVersion::default() && !params.quiet {
        println!("File is encrypted with deprecated algorithm. Please reencrypt now.");
    }

    let cypher = Cypher::new(key);

    if params.output == "-" {
        cypher.decrypt_file(&params.filename, &mut io::stdout())?;
    } else {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&params.output)?;
        let mut lock = match Flock::lock(file, FlockArg::LockExclusive) {
            Ok(l) => l,
            Err((_, e)) => bail!(e),
        };
        cypher.decrypt_file(&params.filename, &mut *lock)?;
        lock.flush()?;
    }
    Ok(())
}

fn run_upgrade_storage(
    params: &CliParams,
    old_key: EncryptionKey,
    new_key: EncryptionKey,
) -> Result<()> {
    let spinner = Spinner::new("Converting", params.quiet);

    let old_cypher = Cypher::new(old_key);
    let old_storage = load_storage_v5(&old_cypher, &params.filename)?;

    let mut new_storage = StorageV5::new();
    let new_cypher = Cypher::new(new_key);
    for (key, item) in old_storage.root.secrets() {
        if let Some(entries) = item.get_entries() {
            for entry in entries {
                let mut secret = entry.encrypted_value().decrypt(&old_cypher)?;
                let new_value = EncryptedValue::encrypt(&new_cypher, &secret)?;
                new_storage.put_at_path("/", key.clone(), new_value, entry.timestamp);
                secret.zeroize();
            }
        }
    }

    save_storage_v5(&new_cypher, &new_storage, &params.filename)?;

    spinner.finish_and_clear();
    Ok(())
}

fn run_interactive(params: &CliParams, key: EncryptionKey) -> Result<()> {
    let cypher = Cypher::new(key);

    let mut interactive_cli = cli::InteractiveCli::new(
        params.prompt.clone(),
        params.insecure_stdout,
        cypher,
        params.filename.clone(),
    );
    interactive_cli.run()?;
    Ok(())
}

/// Returns appropriate Argon2 parameters based on CLI flags.
/// When --insecure-password is used (for testing), returns minimal parameters to speed up tests.
/// Otherwise returns secure default parameters for production use.
fn get_argon2_params(params: &CliParams) -> Argon2Params {
    if params.insecure_password.is_some() {
        Argon2Params::insecure()
    } else {
        Argon2Params::default()
    }
}

// Start background debugger monitoring thread
// Returns a stop guard that needs to be held until the exit of the main thread
fn start_background_debugger_checks() -> ThreadStopGuard {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();

    let handle = std::thread::spawn(move || {
        loop {
            // Check if we should stop
            if stop_flag_clone.load(Ordering::Relaxed) {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(100));

            if is_debugger_attached() {
                eprintln!("\nDebugger attached. Exiting for security.");
                std::process::exit(1);
            }
        }
    });

    ThreadStopGuard::new(stop_flag, handle)
}

fn main() -> Result<()> {
    // Disable core dumps to prevent memory dumps on crash
    let _ = disable_core_dumps();

    let mut params = CliParams::parse();

    // Enable ptrace self-protection to prevent debuggers from attaching
    if !params.insecure_allow_debugging
        && let Err(e) = enable_ptrace_protection()
    {
        eprintln!("Security error: {e}");
        std::process::exit(1);
    }

    if is_debugger_attached() {
        eprintln!("Debugger detected. Exiting for security.");
        std::process::exit(1);
    }

    let _dbg_stop_guard = start_background_debugger_checks();

    let argon2_params = get_argon2_params(&params);
    let mut password = params.insecure_password.take().unwrap_or_else(|| {
        let need_confirmation = params.encrypt || !params.filename.exists();
        get_password(&params.filename, need_confirmation).expect("password")
    });

    if params.encrypt {
        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            &password,
            &argon2_params,
        )?;
        password.zeroize();
        run_encrypt(&params, key)
    } else if params.decrypt {
        let key = EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;
        password.zeroize();
        run_decrypt(&params, key)
    } else if params.update_with.is_some() {
        let spinner = Spinner::new("Deriving encryption keys", params.quiet);

        let main_key =
            EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;

        spinner.set_message("Deriving encryption key for update file");
        let update_file = params
            .update_with
            .as_ref()
            .expect("update_with must be set");
        let update_key =
            EncryptionKey::for_file_with_params(&password, update_file, &argon2_params)?;
        password.zeroize();

        spinner.finish_and_clear();

        cli::update::run_update_with(
            &params.filename,
            update_file,
            main_key,
            update_key,
            params.insecure_stdout,
        )
    } else if params.upgrade_storage {
        let spinner = Spinner::new("Deriving old encryption keys", params.quiet);

        let old_key =
            EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;

        spinner.set_message("Deriving new encryption keys");
        let new_key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            &password,
            &argon2_params,
        )?;
        password.zeroize();

        spinner.finish_and_clear();

        run_upgrade_storage(&params, old_key, new_key)
    } else {
        let spinner = Spinner::new("Deriving encryption key", params.quiet);

        let key = EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;

        spinner.finish_and_clear();

        // Check if storage needs upgrade in interactive mode
        if key.version < CypherVersion::default() && !params.quiet {
            println!("File is encrypted with deprecated algorithm.");
            print!("Would you like to upgrade it now? (y/n): ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes") {
                let spinner = Spinner::new("Deriving new encryption keys", params.quiet);

                let new_key = EncryptionKey::from_password_with_params(
                    CypherVersion::default(),
                    &password,
                    &argon2_params,
                )?;
                password.zeroize();

                spinner.finish_and_clear();

                run_upgrade_storage(&params, key, new_key.clone())?;

                run_interactive(&params, new_key)
            } else {
                password.zeroize();
                run_interactive(&params, key)
            }
        } else {
            password.zeroize();
            run_interactive(&params, key)
        }
    }
}

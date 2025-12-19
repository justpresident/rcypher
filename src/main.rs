mod cli;
use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use cli::InteractiveCli;
use nix::fcntl::{Flock, FlockArg};
use rcypher::*; // Import from lib
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;
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

    /// Don't show loading animation during startup and warnings
    #[arg(long, action, default_value_t = false, hide(true))]
    quiet: bool,

    #[arg(long, default_value = "cypher > ")]
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

fn get_password(params: &CliParams) -> Result<String> {
    match &params.insecure_password {
        Some(passwd) => Ok(passwd.clone()),
        None => Ok(rpassword::prompt_password(format!(
            "Enter Password for {}: ",
            params.filename.display()
        ))?),
    }
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
    let old_storage = load_storage(&old_cypher, &params.filename)?;

    let mut new_storage = Storage::new();
    let new_cypher = Cypher::new(new_key);
    for (key, entries) in old_storage.data {
        for entry in entries {
            let mut secret = entry.value.decrypt(&old_cypher)?;
            let new_value = EncryptedValue::encrypt(&new_cypher, &secret)?;
            new_storage.put_ts(key.clone(), new_value, entry.timestamp);
            secret.zeroize();
        }
    }
    let dir = &params
        .filename
        .parent()
        .expect("Can't get parent dir of a file");
    let mut temp = NamedTempFile::new_in(dir)?;

    let serialized = serialize_storage(&new_storage);
    let encrypted = new_cypher.encrypt(&serialized)?;

    temp.write_all(&encrypted)?;
    temp.persist(&params.filename)?;

    spinner.finish_and_clear();
    Ok(())
}

fn run_interactive(params: &CliParams, key: EncryptionKey) -> Result<()> {
    let cypher = Cypher::new(key);

    let interactive_cli = InteractiveCli::new(
        params.prompt.clone(),
        params.insecure_stdout,
        cypher,
        params.filename.clone(),
    );
    interactive_cli.run()?;
    Ok(())
}

fn main() -> Result<()> {
    let params = CliParams::parse();
    let mut password = get_password(&params)?;

    if params.encrypt {
        let key = EncryptionKey::from_password(CypherVersion::default(), &password)?;
        password.zeroize();
        run_encrypt(&params, key)
    } else if params.decrypt {
        let key = Cypher::encryption_key_for_file(&password, &params.filename)?;
        password.zeroize();
        run_decrypt(&params, key)
    } else if params.update_with.is_some() {
        let spinner = Spinner::new("Deriving encryption keys", params.quiet);

        let main_key = Cypher::encryption_key_for_file(&password, &params.filename)?;

        spinner.set_message("Deriving encryption key for update file");
        let update_file = params
            .update_with
            .as_ref()
            .expect("update_with must be set");
        let update_key = Cypher::encryption_key_for_file(&password, update_file)?;
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

        let old_key = Cypher::encryption_key_for_file(&password, &params.filename)?;

        spinner.set_message("Deriving new encryption keys");
        let new_key = EncryptionKey::from_password(CypherVersion::default(), &password)?;
        password.zeroize();

        spinner.finish_and_clear();

        run_upgrade_storage(&params, old_key, new_key)
    } else {
        let spinner = Spinner::new("Deriving encryption key", params.quiet);

        let key = Cypher::encryption_key_for_file(&password, &params.filename)?;

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

                let new_key = EncryptionKey::from_password(CypherVersion::default(), &password)?;
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

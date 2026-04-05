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
    clippy::missing_panics_doc
)]

use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{SigEvent, SigSet, SigevNotify, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::timer::{Expiration, Timer, TimerSetTimeFlags};
use nix::time::ClockId;
use rcypher::cli::utils::get_password;
use rcypher::{Argon2Params, Cypher, CypherVersion, EncryptionKey, Spinner};
use rcypher::{cli, disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

    #[arg(long, default_value = "cypher > ")]
    prompt: String,

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

fn run_interactive(
    params: &CliParams,
    key: EncryptionKey,
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
) -> Result<()> {
    let cypher = Cypher::new(key);

    let interactive_cli = cli::InteractiveCli::new(
        params.prompt.clone(),
        params.insecure_stdout,
        cypher,
        params.filename.clone(),
        last_activity,
        last_security_check,
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

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// RAII guard that deletes the POSIX timer on drop.
struct SecurityTimerGuard {
    _timer: Timer,
}

/// Start a POSIX interval timer that fires SIGALRM every second.
///
/// A dedicated `sigwait` thread receives each tick and performs two checks:
///   1. Debugger detection — exits immediately if one is found.
///   2. Idle timeout — exits if no successful command has been recorded in
///      `last_activity` within `rcypher::cli::STANDBY_TIMEOUT` seconds.
///      The idle check is skipped while `last_activity` is 0 (non-interactive
///      modes where the value is never set).
///
/// SIGALRM is blocked in the calling thread before the timer is armed, so
/// every subsequent thread inherits the blocked mask and the signal is
/// consumed only by the dedicated handler thread via `sigwait`.
fn start_security_timer(
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
) -> Result<SecurityTimerGuard> {
    // Block SIGALRM in this thread; all threads spawned afterwards inherit
    // the mask, ensuring only our sigwait thread receives the signal.
    let mut alrm_mask = SigSet::empty();
    alrm_mask.add(Signal::SIGALRM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&alrm_mask), None)?;

    let sigevent = SigEvent::new(SigevNotify::SigevSignal {
        signal: Signal::SIGALRM,
        si_value: 0,
    });
    let mut timer = Timer::new(ClockId::CLOCK_MONOTONIC, sigevent)?;
    timer.set(
        Expiration::Interval(Duration::from_secs(1).into()),
        TimerSetTimeFlags::empty(),
    )?;

    std::thread::spawn(move || {
        let mut wait_mask = SigSet::empty();
        wait_mask.add(Signal::SIGALRM);

        let mut prev_time = SystemTime::now();

        loop {
            // Block until the OS delivers the next SIGALRM tick.
            if wait_mask.wait() != Ok(Signal::SIGALRM) {
                continue;
            }

            let now = SystemTime::now();

            // Verify real time moved forward since the last tick.
            // duration_since returns Err if now < prev (clock went backward),
            // or Ok(Duration::ZERO) if frozen. Both map to zero via
            // unwrap_or_default, and is_zero() catches both cases.
            if now.duration_since(prev_time).unwrap_or_default().is_zero() {
                std::process::exit(1);
            }
            prev_time = now;

            // Record heartbeat timestamp so the interactive loop can detect
            // if this thread stops running (e.g. paused by a debugger).
            let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            last_security_check.store(now_secs, Ordering::Relaxed);

            if is_debugger_attached() {
                std::process::exit(1);
            }

            let last_secs = last_activity.load(Ordering::Relaxed);
            if last_secs > 0 && now_secs.saturating_sub(last_secs) > rcypher::cli::STANDBY_TIMEOUT {
                std::process::exit(0);
            }
        }
    });

    Ok(SecurityTimerGuard { _timer: timer })
}

fn main() -> Result<()> {
    // Disable core dumps to prevent memory dumps on crash
    let _ = disable_core_dumps();

    let mut params = CliParams::parse();

    // Enable ptrace self-protection to prevent debuggers from attaching
    if !params.insecure_allow_debugging
        && let Err(_) = enable_ptrace_protection()
    {
        std::process::exit(1);
    }

    if is_debugger_attached() {
        std::process::exit(1);
    }

    let last_activity = Arc::new(AtomicU64::new(0));
    // Initialise to now so the watchdog doesn't fire before the first tick.
    let last_security_check = Arc::new(AtomicU64::new(current_unix_secs()));
    let _security_guard = start_security_timer(last_activity.clone(), last_security_check.clone())?;

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
    } else if let Some(update_file) = &params.update_with {
        let spinner = Spinner::new("Deriving encryption keys", params.quiet);

        let main_key =
            EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;

        spinner.set_message("Deriving encryption key for update file");
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
    } else {
        let spinner = Spinner::new("Deriving encryption key", params.quiet);

        let key = EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;

        spinner.finish_and_clear();

        password.zeroize();
        run_interactive(&params, key, last_activity, last_security_check)
    }
}

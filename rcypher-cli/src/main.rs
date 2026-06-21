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

mod cli;

use crate::cli::utils::{Spinner, confirm_if_weak_password, get_password, prompt_password};
use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use rcypher::{
    Argon2Params, Cypher, CypherVersion, EncryptedValue, EncryptionKey, Storage,
    deserialize_storage, load_storage, serialize_storage,
};
use rcypher::{ContainerFormat, PolicyMetadata, PolicyVault, UnlockSession, parse_policy_vault};
use rcypher::{disable_core_dumps, enable_ptrace_protection, is_debugger_attached};
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(group(
    ArgGroup::new("mode")
        .args(&["encrypt", "decrypt"])
        .multiple(false)
))]
#[command(name = "rcypher")]
#[command(version)]
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

fn run_interactive(params: &CliParams, opened: OpenedStore, clock: SecurityClock) -> Result<()> {
    let interactive_cli = cli::InteractiveCli::new(
        params.prompt.clone(),
        params.insecure_stdout,
        opened.vault,
        opened.from_legacy,
        get_argon2_params(params),
        params.filename.clone(),
        clock,
    );
    interactive_cli.run(opened.storage)?;
    Ok(())
}

/// Unlocks a policy vault by collecting factor secrets until the policy is met.
///
/// Asks for a password in a loop (not per named factor): each entry is tried
/// against every still-unsatisfied factor, satisfied factors are reported, and
/// the loop continues until the policy is satisfied. When `--insecure-password`
/// is set (testing only), that one password is tried once instead of prompting.
fn unlock_interactively(meta: PolicyMetadata, params: &CliParams) -> Result<PolicyVault> {
    let mut session = UnlockSession::new(meta);
    if !session.satisfiable_by_passwords() {
        bail!("this store's policy requires a YubiKey factor, which is not yet supported");
    }

    // Non-interactive testing path: one password, which must satisfy on its own.
    if let Some(pw) = params.insecure_password.as_deref() {
        session.try_password(pw)?;
        if !session.is_complete() {
            bail!("the provided password does not satisfy the unlock policy");
        }
        return session.finish();
    }

    while !session.is_complete() {
        let password = prompt_password("Password (empty to cancel)")?;
        if password.is_empty() {
            bail!("unlock cancelled");
        }

        let spinner = Spinner::new("Checking", params.quiet);
        let matched = session.try_password(&password)?;
        spinner.finish_and_clear();

        match matched {
            None => eprintln!("That password did not match any factor — try again."),
            Some(id) => {
                eprintln!("Factor '{id}' unlocked.");
                if !session.is_complete() {
                    eprintln!("More factors are required to satisfy the policy.");
                }
            }
        }
    }
    session.finish()
}

/// Returns the store password — the one supplied via `--insecure-password`
/// (testing) or prompted from the user. `confirm` asks for a second entry.
fn obtain_store_password(
    params: &CliParams,
    path: &Path,
    confirm: bool,
) -> Result<Zeroizing<String>> {
    params.insecure_password.as_ref().map_or_else(
        || get_password(path, confirm),
        |pw| Ok(Zeroizing::new(pw.clone())),
    )
}

/// An unlocked store — always a policy vault in memory. `from_legacy` is true
/// when it was transparently converted from a legacy (v7) file and is not yet
/// persisted in the current format.
struct OpenedStore {
    vault: PolicyVault,
    storage: Storage,
    from_legacy: bool,
}

/// Opens an existing store, unlocking it. A current-format (v8) file is unlocked
/// against its policy; a legacy (v7) file is decrypted and transparently
/// converted to a policy vault in memory (its password becomes the `primary`
/// factor; values are re-encrypted under a fresh key; the file is rewritten in
/// the new format on the next save).
fn open_existing_store(
    params: &CliParams,
    path: &Path,
    argon2: &Argon2Params,
) -> Result<OpenedStore> {
    match ContainerFormat::probe_file(path)? {
        ContainerFormat::V8 => {
            let data = std::fs::read(path)?;
            let (meta, _payload) = parse_policy_vault(&data)?;
            eprintln!(
                "Unlock policy for {}: {}",
                path.display(),
                meta.policy_expr()
            );
            let vault = unlock_interactively(meta, params)?;
            let payload = vault.load_payload(path)?;
            let storage = deserialize_storage(&payload)?;
            Ok(OpenedStore {
                vault,
                storage,
                from_legacy: false,
            })
        }
        ContainerFormat::V7 => {
            let opened = open_and_convert_legacy(params, path, argon2)?;
            eprintln!(
                "Note: '{}' is a legacy store; it will be upgraded to the current format on the \
                 next write (the original is backed up to {} first).",
                path.display(),
                cli::backup_path(path).display()
            );
            Ok(opened)
        }
    }
}

/// Decrypts a legacy (v7) store and converts it to a policy vault in memory: a
/// fresh random DEK, the unlock password as the `primary` factor, and every value
/// re-encrypted under the new key.
fn open_and_convert_legacy(
    params: &CliParams,
    path: &Path,
    argon2: &Argon2Params,
) -> Result<OpenedStore> {
    let mut password = obtain_store_password(params, path, false)?;
    let spinner = Spinner::new("Unlocking store", params.quiet);
    let result = EncryptionKey::for_file_with_params(&password, path, argon2).and_then(|key| {
        let legacy = Cypher::new(key);
        let mut storage = load_storage(&legacy, path)?;
        let vault = PolicyVault::create(cli::DEFAULT_FACTOR_ID, &password, argon2)?;
        let new_cypher = vault.cypher();
        for entries in storage.data.values_mut() {
            for entry in entries {
                let plaintext = entry.value.decrypt(&legacy)?;
                entry.value = EncryptedValue::encrypt(&new_cypher, &plaintext)?;
            }
        }
        Ok(OpenedStore {
            vault,
            storage,
            from_legacy: true,
        })
    });
    spinner.finish_and_clear();
    password.zeroize();
    result
}

/// Creates a new store as a multi-factor policy vault with a single password
/// factor, persisting an empty store so the file exists for later unlocks.
fn create_store(params: &CliParams, argon2: &Argon2Params) -> Result<OpenedStore> {
    // The password is held in a zeroizing buffer, wiped on drop — including the
    // early returns from the strength check below.
    let mut password = obtain_store_password(params, &params.filename, true)?;

    // Strength-check an interactively chosen password (skip in the test-only
    // `--insecure-password` path, which is non-interactive).
    if params.insecure_password.is_none()
        && !confirm_if_weak_password(&password, &[cli::DEFAULT_FACTOR_ID, "rcypher"])?
    {
        bail!("store creation cancelled (weak password not confirmed)");
    }

    let spinner = Spinner::new("Deriving encryption key", params.quiet);
    let vault = PolicyVault::create(cli::DEFAULT_FACTOR_ID, &password, argon2);
    password.zeroize(); // wipe as soon as the key material is derived
    spinner.finish_and_clear();
    let vault = vault?;

    // Persist an empty store so the file exists as a policy vault.
    vault.save(&serialize_storage(&Storage::new())?, &params.filename)?;
    Ok(OpenedStore {
        vault,
        storage: Storage::new(),
        from_legacy: false,
    })
}

/// Acquires the store for the interactive session: opens an existing one, or
/// creates a new policy vault when the file does not yet exist.
fn acquire_store(params: &CliParams, argon2: &Argon2Params) -> Result<OpenedStore> {
    if params.filename.exists() {
        open_existing_store(params, &params.filename, argon2)
    } else {
        create_store(params, argon2)
    }
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

/// The two shared timestamps that coordinate the security timer thread with the
/// interactive loop. `last_activity` drives the idle timeout; `last_security_check`
/// is the timer's heartbeat (a stale value means the timer thread was paused, e.g.
/// by a debugger).
#[derive(Clone)]
struct SecurityClock {
    last_activity: Arc<AtomicU64>,
    last_security_check: Arc<AtomicU64>,
}

/// RAII guard that disarms the interval timer on drop.
struct SecurityTimerGuard {
    _timer: AlarmTimer,
}

/// Linux — a POSIX per-process interval timer (`timer_create`) on the monotonic
/// clock; dropping the `Timer` deletes the kernel timer.
#[cfg(target_os = "linux")]
struct AlarmTimer {
    _timer: nix::sys::timer::Timer,
}

#[cfg(target_os = "linux")]
fn arm_alarm_timer() -> Result<AlarmTimer> {
    use nix::sys::signal::{SigEvent, SigevNotify};
    use nix::sys::timer::{Expiration, Timer, TimerSetTimeFlags};
    use nix::time::ClockId;

    let sigevent = SigEvent::new(SigevNotify::SigevSignal {
        signal: Signal::SIGALRM,
        si_value: 0,
    });
    let mut timer = Timer::new(ClockId::CLOCK_MONOTONIC, sigevent)?;
    timer.set(
        Expiration::Interval(std::time::Duration::from_secs(1).into()),
        TimerSetTimeFlags::empty(),
    )?;
    Ok(AlarmTimer { _timer: timer })
}

/// Non-Linux Unix (macOS, BSD) — `setitimer(ITIMER_REAL)` delivers SIGALRM on a
/// kernel-driven real-time interval, since macOS has no `timer_create`. This is
/// the same signal-driven design as Linux, NOT a `sleep` loop: the kernel timer
/// fires independently of the handler thread, so a freeze/pause is caught by the
/// monotonic-progress check below. The `Drop` impl disarms it.
#[cfg(all(unix, not(target_os = "linux")))]
struct AlarmTimer;

#[cfg(all(unix, not(target_os = "linux")))]
impl Drop for AlarmTimer {
    fn drop(&mut self) {
        let off = nix::libc::itimerval {
            it_interval: nix::libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: nix::libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        // SAFETY: disarming ITIMER_REAL with a zeroed itimerval.
        unsafe {
            nix::libc::setitimer(nix::libc::ITIMER_REAL, &off, std::ptr::null_mut());
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn arm_alarm_timer() -> Result<AlarmTimer> {
    let interval = nix::libc::itimerval {
        it_interval: nix::libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        },
        it_value: nix::libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        },
    };
    // SAFETY: arming ITIMER_REAL with a valid 1-second itimerval.
    let rc =
        unsafe { nix::libc::setitimer(nix::libc::ITIMER_REAL, &interval, std::ptr::null_mut()) };
    if rc != 0 {
        bail!("Failed to arm interval timer");
    }
    Ok(AlarmTimer)
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
fn start_security_timer(clock: SecurityClock) -> Result<SecurityTimerGuard> {
    let SecurityClock {
        last_activity,
        last_security_check,
    } = clock;

    // Block SIGALRM in this thread; all threads spawned afterwards inherit
    // the mask, ensuring only our sigwait thread receives the signal.
    let mut alrm_mask = SigSet::empty();
    alrm_mask.add(Signal::SIGALRM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&alrm_mask), None)?;

    let timer = arm_alarm_timer()?;

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
            if last_secs > 0 && now_secs.saturating_sub(last_secs) > cli::STANDBY_TIMEOUT {
                std::process::exit(0);
            }
        }
    });

    Ok(SecurityTimerGuard { _timer: timer })
}

fn main() -> Result<()> {
    // Disable core dumps to prevent memory dumps on crash
    let _ = disable_core_dumps();

    let params = CliParams::parse();

    // Enable ptrace self-protection to prevent debuggers from attaching
    if !params.insecure_allow_debugging
        && let Err(_) = enable_ptrace_protection()
    {
        std::process::exit(1);
    }

    if is_debugger_attached() {
        std::process::exit(1);
    }

    let clock = SecurityClock {
        last_activity: Arc::new(AtomicU64::new(0)),
        // Initialise to now so the watchdog doesn't fire before the first tick.
        last_security_check: Arc::new(AtomicU64::new(current_unix_secs())),
    };
    let _security_guard = start_security_timer(clock.clone())?;

    let argon2_params = get_argon2_params(&params);

    if params.encrypt {
        let mut password = obtain_store_password(&params, &params.filename, true)?;
        let key = EncryptionKey::from_password_with_params(
            CypherVersion::default(),
            &password,
            &argon2_params,
        )?;
        password.zeroize(); // wipe eagerly, before the (slower) encryption runs
        run_encrypt(&params, key)
    } else if params.decrypt {
        let mut password = obtain_store_password(&params, &params.filename, false)?;
        let key = EncryptionKey::for_file_with_params(&password, &params.filename, &argon2_params)?;
        password.zeroize(); // wipe eagerly, before the (slower) decryption runs
        run_decrypt(&params, key)
    } else if let Some(update_file) = &params.update_with {
        // Open both stores (each transparently upgraded if legacy), merge the
        // update file into the main one, and persist the main store.
        let main = open_existing_store(&params, &params.filename, &argon2_params)?;
        let update = open_existing_store(&params, update_file, &argon2_params)?;

        let main_cypher = main.vault.cypher();
        let update_cypher = update.vault.cypher();
        let main_vault = main.vault;
        let mut main_storage = main.storage;
        let path = params.filename.clone();
        let mut backup_pending = main.from_legacy;

        cli::update::run_update_with(
            &main_cypher,
            &update_cypher,
            &mut main_storage,
            &update.storage,
            params.insecure_stdout,
            |storage| {
                cli::persist_store(&main_vault, storage, &path, backup_pending)?;
                backup_pending = false;
                Ok(())
            },
        )
    } else {
        let opened = acquire_store(&params, &argon2_params)?;
        run_interactive(&params, opened, clock)
    }
}

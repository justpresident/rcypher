//! Terminal prompts and direct-to-tty output for secrets.
//!
//! Passwords are read without echo (via `rpassword`) into zeroizing buffers, and
//! sensitive output is written straight to the controlling terminal (`/dev/tty`),
//! never through process stdout, so it can't be redirected or snooped.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{Result, bail};
use nix::fcntl::{Flock, FlockArg};
use zeroize::{Zeroize, Zeroizing};

/// Prints `what` straight to the controlling terminal, then zeroizes the buffer.
///
/// Writes to `/dev/tty` rather than process stdout, so a secret can't be snooped
/// from a redirected stdout; the write takes an exclusive advisory lock so
/// concurrent secure prints don't interleave. With `insecure_stdout` (testing
/// only) it falls back to `println!`.
pub fn secure_print(mut what: String, insecure_stdout: bool) -> Result<()> {
    if insecure_stdout {
        println!("{}", &what);
        return Ok(());
    }
    let tty = OpenOptions::new().write(true).open("/dev/tty")?;
    let mut lock = match Flock::lock(tty, FlockArg::LockExclusive) {
        Ok(l) => l,
        Err((_, e)) => bail!(e),
    };
    lock.write_all(what.as_bytes())?;
    lock.write_all(b"\n")?;
    lock.flush()?;

    what.zeroize();
    Ok(())
}

/// Prompts (without echo) for a store password, in a zeroizing buffer.
///
/// With `require_confirmation` it shows the unrecoverable-password warning, asks a
/// second time, and fails unless the two entries match.
pub fn get_password(filename: &Path, require_confirmation: bool) -> Result<Zeroizing<String>> {
    if require_confirmation {
        show_password_warning();
    }

    let password = Zeroizing::new(rpassword::prompt_password(format!(
        "Enter Password for {}: ",
        filename.display()
    ))?);

    if require_confirmation {
        let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm Password: ")?);
        if *password != *confirmation {
            bail!("Passwords do not match");
        }
    }

    Ok(password)
}

/// Prompts (without echo) for a password, returning it in a zeroizing buffer.
/// `prompt` is shown verbatim, followed by `: `.
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(format!(
        "{prompt}: "
    ))?))
}

/// Prompts for a new password, twice, and fails unless the two entries match.
///
/// Used when enrolling a new factor; `label` names what the password is for. The
/// returned password is held in a zeroizing buffer.
pub fn prompt_new_password(label: &str) -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password(format!(
        "New password for {label}: "
    ))?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if *password != *confirmation {
        bail!("Passwords do not match");
    }
    Ok(password)
}

/// Reads a yes/no answer from the controlling terminal (`/dev/tty`), so the
/// prompt works even while an interactive line editor owns stdin. Returns `false`
/// for anything other than an explicit yes.
pub fn read_tty_confirmation(prompt: &str) -> Result<bool> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let mut writer = tty.try_clone()?;
    writer.write_all(prompt.as_bytes())?;
    writer.flush()?;

    let mut reader = BufReader::new(tty);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn show_password_warning() {
    eprintln!("\n╔════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                         ⚠️  IMPORTANT! ⚠️                          ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                    ║");
    eprintln!("║  Your password CANNOT be recovered if lost or forgotten.           ║");
    eprintln!("║  Without it, your encrypted data will be PERMANENTLY inaccessible. ║");
    eprintln!("║                                                                    ║");
    eprintln!("║  → Use a strong, memorable password                                ║");
    eprintln!("║  → Store it under a secret name in another password manager        ║");
    eprintln!("║  → Never share it with anyone                                      ║");
    eprintln!("║                                                                    ║");
    eprintln!("╚════════════════════════════════════════════════════════════════════╝\n");
}

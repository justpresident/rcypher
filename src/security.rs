use anyhow::Result;
use std::sync::OnceLock;

/// Stores the expected parent PID after `PTRACE_TRACEME` is called
static EXPECTED_TRACER_PID: OnceLock<u32> = OnceLock::new();

/// Disable core dumps for this process to prevent memory dumps on crash
#[cfg(target_family = "unix")]
pub fn disable_core_dumps() -> Result<()> {
    use nix::libc::{RLIMIT_CORE, rlimit, setrlimit};

    unsafe {
        let rlim = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if setrlimit(RLIMIT_CORE, &raw const rlim) == -1 {
            return Err(anyhow::anyhow!("Failed to disable core dumps"));
        }
    }
    Ok(())
}

/// Enable ptrace self-protection to prevent debuggers from attaching
///
/// This function implements the secure fork-based approach as described in ptrace(2):
/// 1. Forks the current process
/// 2. Child calls `PTRACE_TRACEME` to be traced by the parent
/// 3. Child immediately queries parent PID via `getppid()`
/// 4. Child stores the parent PID and continues as the main application
/// 5. Parent keeps the child traced for the entire application lifetime
///
/// Returns Err if a debugger is already attached or fork fails.
#[cfg(target_family = "unix")]
pub fn enable_ptrace_protection() -> Result<()> {
    use nix::libc::{_exit, PTRACE_TRACEME, getppid, ptrace};
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, fork};

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: keep the child traced until it exits
            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, status)) => {
                        // Child exited normally, exit with same status
                        unsafe { _exit(status) };
                    }
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        // Child was killed by signal, exit with signal number
                        unsafe { _exit(128 + signal as i32) };
                    }
                    Ok(_) => {
                        // Other wait status (stopped, continued, etc) - keep waiting
                    }
                    Err(e) => {
                        eprintln!("waitpid failed: {e}");
                        unsafe { _exit(1) };
                    }
                }
            }
        }
        Ok(ForkResult::Child) => {
            // Child process: this becomes the main application

            // Get parent PID immediately after fork
            let parent_pid = std::convert::TryInto::<u32>::try_into(unsafe { getppid() })
                .expect("parent pid is positive");

            // Call PTRACE_TRACEME to be traced by parent
            unsafe {
                let result = ptrace(
                    PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<std::ffi::c_void>(),
                    std::ptr::null_mut::<std::ffi::c_void>(),
                );

                if result == -1 {
                    let errno = *nix::libc::__errno_location();
                    if errno == nix::libc::EPERM {
                        return Err(anyhow::anyhow!(
                            "Debugger already attached (ptrace protection failed)"
                        ));
                    }
                    return Err(anyhow::anyhow!(
                        "Failed to enable ptrace protection: errno {errno}"
                    ));
                }
            }

            EXPECTED_TRACER_PID.set(parent_pid).ok();

            // Continue execution as main application
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("Failed to fork: {e}")),
    }
}

#[cfg(not(target_family = "unix"))]
pub fn enable_ptrace_protection() -> Result<()> {
    Ok(())
}

/// Check if a debugger is attached using all available methods for the current platform
/// TODO: implement sysctl check for FreeBSD
pub fn is_debugger_attached() -> bool {
    check_proc_status()
}

/// Method 1: Linux - Check /proc/self/status for `TracerPid`
///
/// After `PTRACE_TRACEME` is called in the forked child, `TracerPid` should equal our parent PID.
/// Returns true if a debugger is detected (`TracerPid` doesn't match expected parent or is 0)
/// OR if the check cannot be performed reliably.
#[cfg(target_os = "linux")]
fn check_proc_status() -> bool {
    // Fail-safe: if we can't read status, assume traced
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return true;
    };

    for line in status.lines() {
        if let Some(tracer_pid_str) = line.strip_prefix("TracerPid:") {
            // Fail-safe: if we can't parse TracerPid, assume traced
            let Ok(tracer_pid) = tracer_pid_str.trim().parse::<u32>() else {
                return true;
            };

            // If ptrace protection was enabled, verify TracerPid matches expected parent
            if let Some(&expected_tracer) = EXPECTED_TRACER_PID.get() {
                // TracerPid should match our expected parent tracer
                // If TracerPid is 0 (stopped tracing) or changed to a different PID,
                // that indicates someone is tampering with debugging
                if tracer_pid != expected_tracer {
                    return true; // Debugger detected or tracing stopped
                }
                return false; // TracerPid matches expected parent - all good
            }

            // Ptrace protection not enabled (e.g., in tests)
            // Fall back to simple check: return true if someone is tracing us
            return tracer_pid != 0;
        }
    }

    // Fail-safe: TracerPid line not found, assume traced
    true
}

#[cfg(not(target_os = "linux"))]
fn check_proc_status() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use nix::libc::getppid;

    use super::*;

    #[test]
    #[cfg(target_family = "unix")]
    fn test_disable_core_dumps() {
        use nix::libc::{RLIMIT_CORE, getrlimit, rlimit};

        // Call disable_core_dumps
        disable_core_dumps().expect("Failed to disable core dumps");

        // Verify that RLIMIT_CORE is actually set to 0
        unsafe {
            let mut rlim = rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            let result = getrlimit(RLIMIT_CORE, &raw mut rlim);
            assert_eq!(result, 0, "getrlimit failed");

            // Both soft and hard limits should be 0
            assert_eq!(rlim.rlim_cur, 0, "Soft limit (rlim_cur) should be 0");
            assert_eq!(rlim.rlim_max, 0, "Hard limit (rlim_max) should be 0");
        }
    }

    #[test]
    #[cfg(not(target_family = "unix"))]
    fn test_disable_core_dumps() {
        // On non-Unix platforms, this should just succeed
        assert!(disable_core_dumps().is_ok());
    }

    #[test]
    // The test verifies that protection mechanics works:
    // - `TracerPid` matches the parent process
    // But it relies on the OS guarantee that only one process can connect as a debugger, it is not
    // verified by the test explicitly
    fn test_ptrace_protection() {
        enable_ptrace_protection().unwrap();
        let parent_pid = unsafe { getppid() } as u32;

        assert_eq!(*(EXPECTED_TRACER_PID.get().unwrap()), parent_pid);

        assert!(!is_debugger_attached());

        // Manually verify TracerPid value from /proc/self/status
        let status =
            std::fs::read_to_string("/proc/self/status").expect("Failed to read /proc/self/status");

        let mut found_tracer_pid = false;
        for line in status.lines() {
            if let Some(tracer_pid_str) = line.strip_prefix("TracerPid:") {
                let tracer_pid: u32 = tracer_pid_str
                    .trim()
                    .parse()
                    .expect("Failed to parse TracerPid");

                found_tracer_pid = true;

                assert_eq!(tracer_pid, parent_pid);
                break;
            }
        }

        assert!(found_tracer_pid, "TracerPid not found in /proc/self/status");
    }
}

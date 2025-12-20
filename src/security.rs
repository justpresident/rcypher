use anyhow::Result;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disable_core_dumps() {
        // Should not fail even if it doesn't work
        assert!(disable_core_dumps().is_ok());
    }
}

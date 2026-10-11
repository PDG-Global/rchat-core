//! Process hardening applied once at startup (finding R-13): the relay's
//! memory holds its identity seed, the RCQ2 queue key (meant to live only
//! on a memory filesystem), the per-boot tag keys and queued ciphertext, so
//! it must never be written to a core file or be readable through ptrace
//! by another process of the same user.

/// Disable core dumps (`RLIMIT_CORE` = 0, soft and hard) and, where the OS
/// has it, mark the process non-dumpable / non-traceable: Linux
/// `prctl(PR_SET_DUMPABLE, 0)`, FreeBSD `procctl(PROC_TRACE_CTL, DISABLE)`.
/// The systemd units also set `LimitCORE=0`; this covers every other way
/// of starting the relay.
///
/// When the limit is already zero (`LimitCORE=0`) setrlimit is not called:
/// the direct unit's `SystemCallFilter=~@resources` forbids it.
///
/// Each step is tried even if an earlier one failed (L-4): a sandbox that
/// refuses setrlimit must not also cost the process its non-dumpable,
/// non-traceable flag. The first error is returned after all steps ran.
pub fn disable_core_dumps() -> std::io::Result<()> {
    run_all(&[&mark_undumpable, &zero_core_limit])
}

/// Run every step; return the first error, if any, after all have run.
fn run_all(steps: &[&dyn Fn() -> std::io::Result<()>]) -> std::io::Result<()> {
    let mut first_error = None;
    for step in steps {
        if let Err(e) = step() {
            first_error.get_or_insert(e);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// `RLIMIT_CORE` = 0 (soft and hard), unless it already is.
fn zero_core_limit() -> std::io::Result<()> {
    if core_limit()? != (0, 0) {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `zero` is a valid, initialised rlimit for the duration of
        // the call; setrlimit only reads it.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Linux `PR_SET_DUMPABLE` 0, FreeBSD `PROC_TRACE_CTL_DISABLE`; nothing
/// elsewhere.
fn mark_undumpable() -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: PR_SET_DUMPABLE takes integer arguments only.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        let mut arg: libc::c_int = libc::PROC_TRACE_CTL_DISABLE;
        // SAFETY: PROC_TRACE_CTL reads one c_int through `data`, which
        // points at `arg` for the duration of the call; id 0 with P_PID is
        // the calling process.
        let rc = unsafe {
            libc::procctl(
                libc::P_PID,
                0,
                libc::PROC_TRACE_CTL,
                (&mut arg as *mut libc::c_int).cast(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Current (soft, hard) `RLIMIT_CORE`.
fn core_limit() -> std::io::Result<(libc::rlim_t, libc::rlim_t)> {
    let mut r = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `r` is a valid out-pointer for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut r) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((r.rlim_cur, r.rlim_max))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-13: after startup hardening no core file can be written, and on
    /// Linux the process is not dumpable.
    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps().expect("hardening applies");
        assert_eq!(core_limit().unwrap(), (0, 0));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: PR_GET_DUMPABLE takes integer arguments only.
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
        }
        // Idempotent (lowering an already-zero limit is allowed).
        disable_core_dumps().expect("second call");
    }

    /// L-4: a step that fails (e.g. setrlimit denied by a sandbox) does not
    /// skip the ones after it; the error is still reported.
    #[test]
    fn a_failing_step_does_not_skip_the_others() {
        use std::cell::Cell;
        let ran = Cell::new(0);
        let fail = || -> std::io::Result<()> {
            ran.set(ran.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        };
        let ok = || -> std::io::Result<()> {
            ran.set(ran.get() + 1);
            Ok(())
        };
        let res = run_all(&[&fail, &ok]);
        assert_eq!(ran.get(), 2, "every step ran");
        assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert!(run_all(&[&ok, &ok]).is_ok());
    }
}

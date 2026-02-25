use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

use crate::lkl::lkl_syscall;
use crate::syscall::SysNrs;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << IOC_DIRSHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT))
        as libc::c_ulong
}

const fn iowr(ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, ty, nr, size)
}

fn seccomp_ioctl_notif_recv() -> libc::c_ulong {
    iowr(
        b'!' as u32,
        0,
        std::mem::size_of::<libc::seccomp_notif>() as u32,
    )
}

fn seccomp_ioctl_notif_send() -> libc::c_ulong {
    iowr(
        b'!' as u32,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>() as u32,
    )
}

fn syscall_is_env_mutating(no: i64) -> bool {
    no == libc::SYS_chdir
        || no == libc::SYS_fchdir
        || no == libc::SYS_setuid
        || no == libc::SYS_setreuid
        || no == libc::SYS_setresuid
        || no == libc::SYS_setgid
        || no == libc::SYS_setregid
        || no == libc::SYS_setresgid
        || no == libc::SYS_setgroups
        || no == libc::SYS_setfsgid
        || no == libc::SYS_umask
}

fn syscall_is_path_sensitive(no: i64) -> bool {
    no == libc::SYS_chdir
        || no == libc::SYS_open
        || no == libc::SYS_openat
        || no == libc::SYS_openat2
        || no == libc::SYS_execveat
        || no == libc::SYS_linkat
        || no == libc::SYS_renameat2
        || no == libc::SYS_symlinkat
        || no == libc::SYS_readlinkat
        || no == libc::SYS_stat
        || no == libc::SYS_lstat
        || no == libc::SYS_newfstatat
        || no == libc::SYS_access
        || no == libc::SYS_faccessat
        || no == libc::SYS_faccessat2
        || no == libc::SYS_mkdir
        || no == libc::SYS_mkdirat
        || no == libc::SYS_unlink
        || no == libc::SYS_unlinkat
        || no == libc::SYS_mount
}

fn syscall_should_skip_lkl_forward(no: i64) -> bool {
    no == libc::SYS_read
        || no == libc::SYS_write
        || no == libc::SYS_readv
        || no == libc::SYS_writev
        || no == libc::SYS_pread64
        || no == libc::SYS_pwrite64
        || no == libc::SYS_recvfrom
        || no == libc::SYS_sendto
        || no == libc::SYS_recvmsg
        || no == libc::SYS_sendmsg
        || no == libc::SYS_poll
        || no == libc::SYS_ppoll
        || no == libc::SYS_select
        || no == libc::SYS_pselect6
        || no == libc::SYS_epoll_wait
        || no == libc::SYS_epoll_pwait
        || no == libc::SYS_epoll_pwait2
        || no == libc::SYS_futex
        || no == libc::SYS_nanosleep
        || no == libc::SYS_clock_nanosleep
        || no == libc::SYS_pause
}

fn normalize_join(base: &Path, input: &Path) -> PathBuf {
    let mut out = if input.is_absolute() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };
    for c in input.components() {
        match c {
            Component::RootDir => out = PathBuf::from("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(n) => out.push(n),
            Component::Prefix(_) => {}
        }
    }
    out
}

fn resolve_path_under_root(root: &Path, cwd: &Path, candidate: &Path) -> Option<PathBuf> {
    let rel = if candidate.is_absolute() {
        PathBuf::from(candidate.strip_prefix("/").ok()?)
    } else {
        cwd.strip_prefix(root).ok()?.join(candidate)
    };
    let combined = normalize_join(root, &rel);
    if combined.starts_with(root) {
        Some(combined)
    } else {
        None
    }
}

fn read_remote_cstring(pid: libc::pid_t, remote_ptr: u64, max_len: usize) -> Option<String> {
    if remote_ptr == 0 {
        return None;
    }
    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_ptr as usize as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
    String::from_utf8(buf[..end].to_vec()).ok()
}

fn install_listener_filter() -> Result<RawFd, String> {
    let arch_check = libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    };
    let arch_match = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    };
    let arch_kill = libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_KILL_PROCESS,
    };
    let load_nr = libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    };
    let allow_execve = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: libc::SYS_execve as u32,
    };
    let ret_notify = libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_USER_NOTIF,
    };
    let ret_allow = libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    };

    let mut prog_vec = vec![
        arch_check,
        arch_match,
        arch_kill,
        load_nr,
        allow_execve,
        ret_notify,
        ret_allow,
    ];
    let prog = libc::sock_fprog {
        len: prog_vec.len() as u16,
        filter: prog_vec.as_mut_ptr(),
    };

    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs != 0 {
        return Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd as RawFd)
}

fn notify_send(fd: RawFd, resp: &libc::seccomp_notif_resp) -> Result<(), String> {
    let rc = unsafe {
        libc::ioctl(
            fd,
            seccomp_ioctl_notif_send(),
            resp as *const libc::seccomp_notif_resp,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        let raw = e.raw_os_error();
        if raw == Some(libc::ENOENT)
            || raw == Some(libc::ESRCH)
            || raw == Some(libc::EINTR)
            || raw == Some(libc::EAGAIN)
        {
            return Ok(());
        }
        return Err(format!("SECCOMP_IOCTL_NOTIF_SEND failed: {e}"));
    }
    Ok(())
}

fn notify_recv(fd: RawFd, req: &mut libc::seccomp_notif) -> Result<(), String> {
    let rc = unsafe {
        libc::ioctl(
            fd,
            seccomp_ioctl_notif_recv(),
            req as *mut libc::seccomp_notif,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR)
            || e.raw_os_error() == Some(libc::EAGAIN)
            || e.raw_os_error() == Some(libc::ENOENT)
        {
            return Ok(());
        }
        return Err(format!("SECCOMP_IOCTL_NOTIF_RECV failed: {e}"));
    }
    Ok(())
}

pub(crate) fn run_seccomp_forward_to_lkl(
    _sysnrs: &SysNrs,
    host_cmd: &str,
    command_args: &[String],
    _forward_syscall: &[String],
    host_root: Option<&Path>,
    host_workdir: Option<&Path>,
    _forward_verbose: bool,
) -> Result<(), String> {
    // Temporary safety fallback:
    // the in-process seccomp user-notify path is currently unstable and can terminate
    // the runtime with SIGSYS under interactive workloads. Keep command execution
    // stable while preserving root/workdir confinement checks.
    let sandbox_root = host_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let start_cwd = host_workdir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sandbox_root.clone());

    if !start_cwd.starts_with(&sandbox_root) {
        return Err(format!(
            "sandbox start cwd escapes root: cwd={} root={}",
            start_cwd.display(),
            sandbox_root.display()
        ));
    }

    let mut cmd = Command::new(host_cmd);
    cmd.args(command_args);
    cmd.current_dir(&start_cwd);

    let status = cmd
        .status()
        .map_err(|e| format!("failed to execute host command '{host_cmd}': {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("host command exited unsuccessfully: '{}' status={status}", host_cmd))
    }
}

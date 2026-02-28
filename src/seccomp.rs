use std::ffi::{CStr, CString, c_void};
use std::io::Read;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::lkl::{close_fd, parse_elf_interp, lkl_syscall6};
use crate::syscall::{
    AT_FDCWD_LINUX, OpenHow, SysNrs, lkl_sys_chdir, lkl_sys_close, lkl_sys_dup, lkl_sys_dup3,
    lkl_sys_faccessat2, lkl_sys_fchmodat, lkl_sys_fchownat, lkl_sys_fcntl, lkl_sys_fstat,
    lkl_sys_fchdir, lkl_sys_getcwd, lkl_sys_getdents, lkl_sys_getdents64, lkl_sys_getegid,
    lkl_sys_geteuid, lkl_sys_getgid, lkl_sys_getgroups, lkl_sys_getuid, lkl_sys_lseek,
    lkl_sys_mkdir, lkl_sys_mkdirat, lkl_sys_mount, lkl_sys_newfstatat, lkl_sys_openat,
    lkl_sys_openat2, lkl_sys_pread64, lkl_sys_read, lkl_sys_renameat2, lkl_sys_setfsgid,
    lkl_sys_setgid, lkl_sys_setgroups, lkl_sys_setregid, lkl_sys_setresgid, lkl_sys_setresuid,
    lkl_sys_setreuid, lkl_sys_setuid, lkl_sys_socket, lkl_sys_statx, lkl_sys_umount2, lkl_sys_unlinkat, lkl_sys_write,
};

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_CURRENT: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_CURRENT: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const HOST_NR_OPENAT: i32 = 257;
#[cfg(target_arch = "x86_64")]
const HOST_NR_OPENAT2: i32 = 437;
#[cfg(target_arch = "x86_64")]
const HOST_NR_OPEN: i32 = 2;
#[cfg(target_arch = "x86_64")]
const HOST_NR_STAT: i32 = 4;
#[cfg(target_arch = "x86_64")]
const HOST_NR_LSTAT: i32 = 6;
#[cfg(target_arch = "x86_64")]
const HOST_NR_ACCESS: i32 = 21;
#[cfg(target_arch = "x86_64")]
const HOST_NR_RENAME: i32 = 82;
#[cfg(target_arch = "x86_64")]
const HOST_NR_MKDIR: i32 = 83;
#[cfg(target_arch = "x86_64")]
const HOST_NR_RMDIR: i32 = 84;
#[cfg(target_arch = "x86_64")]
const HOST_NR_UNLINK: i32 = 87;
#[cfg(target_arch = "x86_64")]
const HOST_NR_CHMOD: i32 = 90;
#[cfg(target_arch = "x86_64")]
const HOST_NR_CHOWN: i32 = 92;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FSTAT: i32 = 5;
#[cfg(target_arch = "x86_64")]
const HOST_NR_NEWFSTATAT: i32 = 262;
#[cfg(target_arch = "x86_64")]
const HOST_NR_STATX: i32 = 332;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FACCESSAT2: i32 = 439;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETDENTS64: i32 = 217;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETDENTS: i32 = 78;
#[cfg(target_arch = "x86_64")]
const HOST_NR_MKDIRAT: i32 = 258;
#[cfg(target_arch = "x86_64")]
const HOST_NR_UNLINKAT: i32 = 263;
#[cfg(target_arch = "x86_64")]
const HOST_NR_RENAMEAT2: i32 = 316;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FCHMODAT: i32 = 268;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FCHOWNAT: i32 = 260;
#[cfg(target_arch = "x86_64")]
const HOST_NR_CLOSE: i32 = 3;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SENDMSG: i32 = 46;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SOCKET: i32 = 41;
#[cfg(target_arch = "x86_64")]
const HOST_NR_CONNECT: i32 = 42;
#[cfg(target_arch = "x86_64")]
const HOST_NR_BIND: i32 = 49;
#[cfg(target_arch = "x86_64")]
const HOST_NR_LISTEN: i32 = 50;
#[cfg(target_arch = "x86_64")]
const HOST_NR_ACCEPT: i32 = 43;
#[cfg(target_arch = "x86_64")]
const HOST_NR_ACCEPT4: i32 = 288;
#[cfg(target_arch = "x86_64")]
const HOST_NR_EXIT: i32 = 60;
#[cfg(target_arch = "x86_64")]
const HOST_NR_EXIT_GROUP: i32 = 231;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FCNTL: i32 = 72;
#[cfg(target_arch = "x86_64")]
const HOST_NR_DUP: i32 = 32;
#[cfg(target_arch = "x86_64")]
const HOST_NR_DUP2: i32 = 33;
#[cfg(target_arch = "x86_64")]
const HOST_NR_DUP3: i32 = 292;
#[cfg(target_arch = "x86_64")]
const HOST_NR_READ: i32 = 0;
#[cfg(target_arch = "x86_64")]
const HOST_NR_WRITE: i32 = 1;
#[cfg(target_arch = "x86_64")]
const HOST_NR_PREAD64: i32 = 17;
#[cfg(target_arch = "x86_64")]
const HOST_NR_LSEEK: i32 = 8;
#[cfg(target_arch = "x86_64")]
const HOST_NR_CHDIR: i32 = 80;
#[cfg(target_arch = "x86_64")]
const HOST_NR_FCHDIR: i32 = 81;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETCWD: i32 = 79;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETUID: i32 = 102;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETEUID: i32 = 107;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETRESUID: i32 = 118;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETGID: i32 = 104;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETEGID: i32 = 108;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETRESGID: i32 = 120;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETUID: i32 = 105;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETREUID: i32 = 113;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETRESUID: i32 = 117;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETGID: i32 = 106;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETREGID: i32 = 114;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETRESGID: i32 = 119;
#[cfg(target_arch = "x86_64")]
const HOST_NR_GETGROUPS: i32 = 115;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETGROUPS: i32 = 116;
#[cfg(target_arch = "x86_64")]
const HOST_NR_SETFSGID: i32 = 123;
#[cfg(target_arch = "x86_64")]
const HOST_NR_MOUNT: i32 = 165;
#[cfg(target_arch = "x86_64")]
const HOST_NR_UMOUNT2: i32 = 166;
#[cfg(target_arch = "x86_64")]
const HOST_NR_EXECVE: i32 = 59;
#[cfg(target_arch = "x86_64")]
const HOST_NR_EXECVEAT: i32 = 322;

#[cfg(target_arch = "aarch64")]
const HOST_NR_OPENAT: i32 = 56;
#[cfg(target_arch = "aarch64")]
const HOST_NR_OPENAT2: i32 = 437;
#[cfg(target_arch = "aarch64")]
const HOST_NR_OPEN: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_STAT: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_LSTAT: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_ACCESS: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_RENAME: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_MKDIR: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_RMDIR: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_UNLINK: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_CHMOD: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_CHOWN: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FSTAT: i32 = 80;
#[cfg(target_arch = "aarch64")]
const HOST_NR_NEWFSTATAT: i32 = 79;
#[cfg(target_arch = "aarch64")]
const HOST_NR_STATX: i32 = 291;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FACCESSAT2: i32 = 439;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETDENTS64: i32 = 61;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETDENTS: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_MKDIRAT: i32 = 34;
#[cfg(target_arch = "aarch64")]
const HOST_NR_UNLINKAT: i32 = 35;
#[cfg(target_arch = "aarch64")]
const HOST_NR_RENAMEAT2: i32 = 276;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FCHMODAT: i32 = 53;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FCHOWNAT: i32 = 54;
#[cfg(target_arch = "aarch64")]
const HOST_NR_CLOSE: i32 = 57;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SENDMSG: i32 = 211;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SOCKET: i32 = 198;
#[cfg(target_arch = "aarch64")]
const HOST_NR_CONNECT: i32 = 203;
#[cfg(target_arch = "aarch64")]
const HOST_NR_BIND: i32 = 200;
#[cfg(target_arch = "aarch64")]
const HOST_NR_LISTEN: i32 = 201;
#[cfg(target_arch = "aarch64")]
const HOST_NR_ACCEPT: i32 = 202;
#[cfg(target_arch = "aarch64")]
const HOST_NR_ACCEPT4: i32 = 242;
#[cfg(target_arch = "aarch64")]
const HOST_NR_EXIT: i32 = 93;
#[cfg(target_arch = "aarch64")]
const HOST_NR_EXIT_GROUP: i32 = 94;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FCNTL: i32 = 25;
#[cfg(target_arch = "aarch64")]
const HOST_NR_DUP: i32 = 23;
#[cfg(target_arch = "aarch64")]
const HOST_NR_DUP2: i32 = -1;
#[cfg(target_arch = "aarch64")]
const HOST_NR_DUP3: i32 = 24;
#[cfg(target_arch = "aarch64")]
const HOST_NR_READ: i32 = 63;
#[cfg(target_arch = "aarch64")]
const HOST_NR_WRITE: i32 = 64;
#[cfg(target_arch = "aarch64")]
const HOST_NR_PREAD64: i32 = 67;
#[cfg(target_arch = "aarch64")]
const HOST_NR_LSEEK: i32 = 62;
#[cfg(target_arch = "aarch64")]
const HOST_NR_CHDIR: i32 = 49;
#[cfg(target_arch = "aarch64")]
const HOST_NR_FCHDIR: i32 = 50;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETCWD: i32 = 17;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETUID: i32 = 174;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETEUID: i32 = 175;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETRESUID: i32 = 148;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETGID: i32 = 176;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETEGID: i32 = 177;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETRESGID: i32 = 150;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETUID: i32 = 146;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETREUID: i32 = 145;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETRESUID: i32 = 147;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETGID: i32 = 144;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETREGID: i32 = 143;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETRESGID: i32 = 149;
#[cfg(target_arch = "aarch64")]
const HOST_NR_GETGROUPS: i32 = 158;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETGROUPS: i32 = 159;
#[cfg(target_arch = "aarch64")]
const HOST_NR_SETFSGID: i32 = 152;
#[cfg(target_arch = "aarch64")]
const HOST_NR_MOUNT: i32 = 40;
#[cfg(target_arch = "aarch64")]
const HOST_NR_UMOUNT2: i32 = 39;
#[cfg(target_arch = "aarch64")]
const HOST_NR_EXECVE: i32 = 221;
#[cfg(target_arch = "aarch64")]
const HOST_NR_EXECVEAT: i32 = 281;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const FORWARD_FD_BASE: libc::c_long = 4096;
const FORWARD_MAX_PATH_LEN: usize = 4096;
const FORWARD_IO_CHUNK_LEN: usize = 128 * 1024;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u64 {
    ((dir as u64) << IOC_DIRSHIFT)
        | ((ty as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

const fn iowr<T>(ty: u32, nr: u32) -> u64 {
    ioc(
        IOC_READ | IOC_WRITE,
        ty,
        nr,
        std::mem::size_of::<T>() as u32,
    )
}

const fn iow<T>(ty: u32, nr: u32) -> u64 {
    ioc(IOC_WRITE, ty, nr, std::mem::size_of::<T>() as u32)
}

fn seccomp_ioctl_notif_recv() -> u64 {
    iowr::<libc::seccomp_notif>(b'!' as u32, 0)
}

fn seccomp_ioctl_notif_send() -> u64 {
    iowr::<libc::seccomp_notif_resp>(b'!' as u32, 1)
}

fn seccomp_ioctl_notif_addfd() -> u64 {
    iow::<libc::seccomp_notif_addfd>(b'!' as u32, 3)
}

/// Returns normalized (mode, uid, gid) for a given guest path.
/// This is used to present consistent permissions regardless of host filesystem.
fn normalized_permissions(path: &CStr) -> Option<(libc::mode_t, libc::uid_t, libc::gid_t)> {
    let bytes = path.to_bytes();
    let path_str = std::str::from_utf8(bytes).ok()?;
    
    // Common paths that should be normalized
    
    // /tmp - sticky bit + world writable
    if path_str == "/tmp" {
        return Some((0o1777, 0, 0));
    }
    
    // /proc and /sys - read-only
    if path_str == "/proc" || path_str == "/sys" {
        return Some((0o555, 0, 0));
    }
    
    // /home directory
    if path_str == "/home" {
        return Some((0o755, 0, 0));
    }
    
    // /etc directory and special files
    if path_str == "/etc" {
        return Some((0o755, 0, 0));
    }
    if path_str == "/etc/passwd" {
        return Some((0o644, 0, 0));
    }
    if path_str == "/etc/shadow" || path_str == "/etc/gshadow" {
        return Some((0o640, 0, 0)); // root:root
    }
    
    // /var directory structure
    if path_str == "/var" || path_str == "/var/lib" || path_str == "/var/cache" || 
       path_str == "/var/log" || path_str == "/var/run" || path_str == "/var/spool" ||
       path_str == "/var/tmp" || path_str == "/var/www" || path_str == "/var/mail" ||
       path_str.starts_with("/var/lib/") || path_str.starts_with("/var/cache/") ||
       path_str.starts_with("/var/log/") || path_str.starts_with("/var/spool/") ||
       path_str.starts_with("/var/www/") || path_str.starts_with("/var/mail/") {
        return Some((0o755, 0, 0));
    }
    
    // /usr directory structure  
    if path_str == "/usr" || path_str == "/usr/local" || path_str == "/usr/lib" ||
       path_str == "/usr/lib64" || path_str == "/usr/share" || path_str == "/usr/include" ||
       path_str == "/usr/src" || path_str.starts_with("/usr/lib/") || 
       path_str.starts_with("/usr/share/") || path_str.starts_with("/usr/include/") ||
       path_str.starts_with("/usr/src/") || path_str.starts_with("/usr/local/") {
        return Some((0o755, 0, 0));
    }
    
    // /lib directories
    if path_str == "/lib" || path_str == "/lib64" || path_str == "/lib32" ||
       path_str == "/libx32" || path_str.starts_with("/lib/") || path_str.starts_with("/lib64/") ||
       path_str.starts_with("/lib32/") || path_str.starts_with("/libx32/") {
        return Some((0o755, 0, 0));
    }
    
    // /etc/apt and dpkg directories
    if path_str == "/etc/apt" || path_str == "/etc/dpkg" || path_str.starts_with("/etc/apt/") ||
       path_str.starts_with("/etc/dpkg/") || path_str.starts_with("/etc/alternatives/") {
        return Some((0o755, 0, 0));
    }
    
    // /dev special files
    if path_str == "/dev/null" || path_str == "/dev/zero" ||
       path_str == "/dev/random" || path_str == "/dev/urandom" {
        return Some((0o666, 0, 0));
    }
    if path_str == "/dev/tty" {
        return Some((0o666, 0, 5)); // root:tty
    }
    if path_str == "/dev/console" {
        return Some((0o600, 0, 0));
    }
    
    // System binary directories
    let is_bin_dir = path_str == "/bin" || path_str == "/usr/bin" ||
                     path_str == "/sbin" || path_str == "/usr/sbin" ||
                     path_str == "/usr/local/bin" || path_str == "/usr/local/sbin";
    
    if is_bin_dir {
        return Some((0o755, 0, 0));
    }
    
    // Check if path is in a binary directory (for binaries)
    let in_bin_dir = path_str.starts_with("/bin/") ||
                     path_str.starts_with("/usr/bin/") ||
                     path_str.starts_with("/sbin/") ||
                     path_str.starts_with("/usr/sbin/") ||
                     path_str.starts_with("/usr/local/bin/") ||
                     path_str.starts_with("/usr/local/sbin/");
    
    if in_bin_dir {
        // Known setuid/setgid binaries
        let is_setuid_binary = path_str.ends_with("/passwd") ||
                               path_str.ends_with("/su") ||
                               path_str.ends_with("/sudo") ||
                               path_str.ends_with("/mount") ||
                               path_str.ends_with("/umount") ||
                               path_str.ends_with("/ping") ||
                               path_str.ends_with("/ping6") ||
                               path_str.ends_with("/newgrp") ||
                               path_str.ends_with("/chfn") ||
                               path_str.ends_with("/chsh") ||
                               path_str.ends_with("/gpasswd");
        
        if is_setuid_binary {
            return Some((0o4755, 0, 0)); // setuid root
        }
        
        // Regular binaries
        return Some((0o755, 0, 0));
    }
    
    // User home directories under /home
    if path_str.starts_with("/home/") {
        // The home directory itself (e.g., /home/user)
        let components: Vec<&str> = path_str.split('/').collect();
        if components.len() == 3 && !components[2].is_empty() {
            // This is a direct child of /home - treat as user home
            // Use a hash of the username to generate consistent uid > 1000
            let username = components[2];
            let uid = 1000 + (hash_username(username) % 64000);
            return Some((0o700, uid, uid));
        }
    }
    
    // /root home directory
    if path_str == "/root" {
        return Some((0o700, 0, 0));
    }
    
    None
}

/// Simple hash function for generating consistent UIDs from usernames
fn hash_username(name: &str) -> libc::uid_t {
    let mut hash: u32 = 5381;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash as libc::uid_t
}

fn syscall_name_from_nr(nr: i32) -> &'static str {
    if nr == HOST_NR_OPENAT {
        "openat"
    } else if nr == HOST_NR_OPENAT2 {
        "openat2"
    } else if nr == HOST_NR_READ {
        "read"
    } else if nr == HOST_NR_WRITE {
        "write"
    } else if nr == HOST_NR_PREAD64 {
        "pread64"
    } else if nr == HOST_NR_LSEEK {
        "lseek"
    } else if nr == HOST_NR_CLOSE {
        "close"
    } else if nr == HOST_NR_FSTAT {
        "fstat"
    } else if nr == HOST_NR_NEWFSTATAT {
        "newfstatat"
    } else if nr == HOST_NR_STATX {
        "statx"
    } else if nr == HOST_NR_FACCESSAT2 {
        "faccessat2"
    } else if nr == HOST_NR_GETDENTS64 {
        "getdents64"
    } else if nr == HOST_NR_GETDENTS {
        "getdents"
    } else if nr == HOST_NR_CHDIR {
        "chdir"
    } else if nr == HOST_NR_FCHDIR {
        "fchdir"
    } else if nr == HOST_NR_GETCWD {
        "getcwd"
    } else if nr == HOST_NR_SOCKET {
        "socket"
    } else if nr == HOST_NR_CONNECT {
        "connect"
    } else if nr == HOST_NR_BIND {
        "bind"
    } else if nr == HOST_NR_LISTEN {
        "listen"
    } else if nr == HOST_NR_ACCEPT {
        "accept"
    } else if nr == HOST_NR_ACCEPT4 {
        "accept4"
    } else if nr == HOST_NR_EXECVE {
        "execve"
    } else if nr == HOST_NR_EXECVEAT {
        "execveat"
    } else {
        "unknown"
    }
}

enum SeccompDispatch {
    Continue,
    Return { val: i64, error: i32 },
}

#[derive(Default)]
struct ForwardFdTable {
    next_fd: libc::c_long,
    lkl_by_forward_fd: std::collections::HashMap<libc::c_long, libc::c_long>,
    mirror_tty_by_forward_fd: std::collections::HashMap<libc::c_long, bool>,
}

impl ForwardFdTable {
    fn new() -> Self {
        Self {
            next_fd: FORWARD_FD_BASE,
            lkl_by_forward_fd: std::collections::HashMap::new(),
            mirror_tty_by_forward_fd: std::collections::HashMap::new(),
        }
    }

    fn insert(&mut self, lkl_fd: libc::c_long, mirror_tty: bool) -> libc::c_long {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.lkl_by_forward_fd.insert(fd, lkl_fd);
        self.mirror_tty_by_forward_fd.insert(fd, mirror_tty);
        fd
    }

    fn insert_at(&mut self, fd: libc::c_long, lkl_fd: libc::c_long, mirror_tty: bool) {
        self.lkl_by_forward_fd.insert(fd, lkl_fd);
        self.mirror_tty_by_forward_fd.insert(fd, mirror_tty);
        if fd >= self.next_fd {
            self.next_fd = fd + 1;
        }
    }

    fn get_lkl(&self, fd: libc::c_long) -> Option<libc::c_long> {
        self.lkl_by_forward_fd.get(&fd).copied()
    }

    fn remove(&mut self, fd: libc::c_long) -> Option<libc::c_long> {
        let _ = self.mirror_tty_by_forward_fd.remove(&fd);
        self.lkl_by_forward_fd.remove(&fd)
    }

    fn should_mirror_tty(&self, fd: libc::c_long) -> bool {
        self.mirror_tty_by_forward_fd
            .get(&fd)
            .copied()
            .unwrap_or(false)
    }
}

fn is_tty_like_path(path: &CStr) -> bool {
    let b = path.to_bytes();
    b == b"/dev/tty"
        || b.starts_with(b"/dev/tty")
        || b.starts_with(b"/dev/pts/")
        || b == b"/dev/console"
}

fn is_loader_runtime_path(path: &CStr) -> bool {
    let b = path.to_bytes();
    b == b"/etc/ld.so.cache"
        || b == b"/etc/ld.so.preload"
        || b.starts_with(b"/lib/")
        || b.starts_with(b"/lib64/")
        || b.starts_with(b"/usr/lib/")
        || b.starts_with(b"/usr/lib64/")
}

fn seccomp_errno_reply(errno: i32) -> SeccompDispatch {
    let errno = if errno <= 0 { libc::EIO } else { errno };
    SeccompDispatch::Return { val: 0, error: errno }
}

fn seccomp_value_reply(val: i64) -> SeccompDispatch {
    SeccompDispatch::Return { val, error: 0 }
}

fn seccomp_from_lkl_ret(ret: libc::c_long) -> SeccompDispatch {
    if ret < 0 {
        seccomp_errno_reply((-ret) as i32)
    } else {
        seccomp_value_reply(ret as i64)
    }
}

fn seccomp_response_for(id: u64, dispatch: SeccompDispatch) -> libc::seccomp_notif_resp {
    match dispatch {
        SeccompDispatch::Continue => libc::seccomp_notif_resp {
            id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        },
        SeccompDispatch::Return { val, error } => libc::seccomp_notif_resp {
            id,
            val,
            // USER_NOTIF expects negative errno in `error`.
            // Passing positive errno makes syscalls appear to succeed (e.g. ENOENT -> fd 2).
            error: if error == 0 { 0 } else { -error.abs() },
            flags: 0,
        },
    }
}

fn os_errno(default_errno: i32) -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default_errno)
}

fn process_vm_read_exact(pid: libc::pid_t, remote_addr: u64, out: &mut [u8]) -> Result<(), i32> {
    if out.is_empty() {
        return Ok(());
    }
    let local_iov = libc::iovec {
        iov_base: out.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: out.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as usize as *mut libc::c_void,
        iov_len: out.len(),
    };
    let ret = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if ret < 0 {
        return Err(os_errno(libc::EIO));
    }
    if ret as usize != out.len() {
        return Err(libc::EIO);
    }
    Ok(())
}

fn process_vm_write_exact(pid: libc::pid_t, remote_addr: u64, inp: &[u8]) -> Result<(), i32> {
    if inp.is_empty() {
        return Ok(());
    }
    let local_iov = libc::iovec {
        iov_base: inp.as_ptr().cast::<libc::c_void>() as *mut libc::c_void,
        iov_len: inp.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as usize as *mut libc::c_void,
        iov_len: inp.len(),
    };
    let ret = unsafe { libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if ret < 0 {
        return Err(os_errno(libc::EIO));
    }
    if ret as usize != inp.len() {
        return Err(libc::EIO);
    }
    Ok(())
}

fn read_remote_c_string(pid: libc::pid_t, remote_addr: u64, max_len: usize) -> Result<CString, i32> {
    if remote_addr == 0 {
        return Err(libc::EFAULT);
    }
    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as usize as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if n <= 0 {
        return Err(os_errno(libc::EIO));
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
    let slice = &buf[..end];
    CString::new(slice).map_err(|_| libc::EINVAL)
}

fn read_remote_open_how(pid: libc::pid_t, remote_addr: u64, size: u64) -> Result<OpenHow, i32> {
    if remote_addr == 0 {
        return Err(libc::EFAULT);
    }
    let expected = std::mem::size_of::<OpenHow>() as u64;
    if size < expected {
        return Err(libc::EINVAL);
    }
    if size > expected {
        return Err(libc::E2BIG);
    }
    let mut how = OpenHow::default();
    let out = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut how as *mut OpenHow).cast::<u8>(),
            std::mem::size_of::<OpenHow>(),
        )
    };
    process_vm_read_exact(pid, remote_addr, out)?;
    Ok(how)
}

fn to_c_long_arg(v: u64) -> libc::c_long {
    v as i64 as libc::c_long
}

fn to_dirfd_arg(v: u64) -> libc::c_long {
    (v as u32 as i32) as libc::c_long
}

fn to_usize_arg(v: u64) -> Result<usize, i32> {
    usize::try_from(v).map_err(|_| libc::EINVAL)
}

fn add_remote_ptr(base: u64, delta: usize) -> Result<u64, i32> {
    base.checked_add(delta as u64).ok_or(libc::EOVERFLOW)
}

fn is_lkl_virtual_path(path: &CStr) -> bool {
    let b = path.to_bytes();
    b == b"/proc"
        || b.starts_with(b"/proc/")
        || b == b"/sys"
        || b.starts_with(b"/sys/")
        || b == b"/dev"
        || b.starts_with(b"/dev/")
}

fn normalize_virtual_relative_path(path: &CStr) -> Option<CString> {
    let mut b = path.to_bytes();
    if b.starts_with(b"./") {
        b = &b[2..];
    }
    let (prefix, rest): (&[u8], &[u8]) = if b == b"proc" {
        (&b"/proc"[..], &b""[..])
    } else if let Some(tail) = b.strip_prefix(b"proc/") {
        (&b"/proc"[..], tail)
    } else if b == b"sys" {
        (&b"/sys"[..], &b""[..])
    } else if let Some(tail) = b.strip_prefix(b"sys/") {
        (&b"/sys"[..], tail)
    } else if b == b"dev" {
        (&b"/dev"[..], &b""[..])
    } else if let Some(tail) = b.strip_prefix(b"dev/") {
        (&b"/dev"[..], tail)
    } else {
        return None;
    };

    let mut out = Vec::with_capacity(prefix.len() + if rest.is_empty() { 0 } else { 1 + rest.len() });
    out.extend_from_slice(prefix);
    if !rest.is_empty() {
        out.push(b'/');
        out.extend_from_slice(rest);
    }
    CString::new(out).ok()
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

fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from_parts: Vec<&std::ffi::OsStr> = from
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    let to_parts: Vec<&std::ffi::OsStr> = to
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    let mut common = 0usize;
    while common < from_parts.len()
        && common < to_parts.len()
        && from_parts[common] == to_parts[common]
    {
        common += 1;
    }
    let mut out = PathBuf::new();
    for _ in common..from_parts.len() {
        out.push("..");
    }
    for part in &to_parts[common..] {
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

fn read_proc_cwd(pid: libc::pid_t) -> Result<PathBuf, i32> {
    let link = PathBuf::from(format!("/proc/{pid}/cwd"));
    std::fs::read_link(&link).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

fn read_proc_fd_path(pid: libc::pid_t, fd: libc::c_long) -> Result<PathBuf, i32> {
    if fd < 0 {
        return Err(libc::EBADF);
    }
    let link = PathBuf::from(format!("/proc/{pid}/fd/{fd}"));
    std::fs::read_link(&link).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

fn guest_path_from_host(host_path: &Path, root: &Path) -> Option<String> {
    if root == Path::new("/") {
        return Some(host_path.to_string_lossy().into_owned());
    }
    let rel = host_path.strip_prefix(root).ok()?;
    if rel.as_os_str().is_empty() {
        return Some(String::from("/"));
    }
    Some(format!("/{}", rel.to_string_lossy()))
}

fn translate_path_for_lkl(
    pid: libc::pid_t,
    path: &CStr,
    host_root: Option<&Path>,
) -> Result<CString, i32> {
    if is_lkl_virtual_path(path) {
        return Ok(path.to_owned());
    }
    if let Some(norm) = normalize_virtual_relative_path(path) {
        return Ok(norm);
    }
    let Some(root) = host_root else {
        return Ok(path.to_owned());
    };
    let cwd = read_proc_cwd(pid)?;
    let input_path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
    let resolved = if input_path.is_absolute() {
        let rel = input_path.strip_prefix("/").map_err(|_| libc::EINVAL)?;
        normalize_join(root, rel)
    } else {
        normalize_join(&cwd, input_path)
    };
    if !resolved.starts_with(root) {
        return Err(libc::EPERM);
    }
    let guest_path = guest_path_from_host(&resolved, root).ok_or(libc::EPERM)?;
    CString::new(guest_path).map_err(|_| libc::EINVAL)
}

fn translate_path_for_host(
    pid: libc::pid_t,
    path: &CStr,
    dirfd: libc::c_long,
    host_root: Option<&Path>,
) -> Result<CString, i32> {
    if is_lkl_virtual_path(path) {
        return Ok(path.to_owned());
    }
    if let Some(norm) = normalize_virtual_relative_path(path) {
        return Ok(norm);
    }
    let Some(root) = host_root else {
        return Ok(path.to_owned());
    };
    let input_path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
    let base = if input_path.is_absolute() {
        PathBuf::from("/")
    } else if dirfd == AT_FDCWD_LINUX {
        read_proc_cwd(pid)?
    } else {
        read_proc_fd_path(pid, dirfd)?
    };
    let resolved = if input_path.is_absolute() {
        let rel = input_path.strip_prefix("/").map_err(|_| libc::EINVAL)?;
        normalize_join(root, rel)
    } else {
        normalize_join(&base, input_path)
    };
    if !resolved.starts_with(root) {
        return Err(libc::EPERM);
    }
    CString::new(resolved.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
}

fn resolve_open_dirfd(path: &CStr, dirfd: libc::c_long, table: &ForwardFdTable) -> Option<libc::c_long> {
    if path.to_bytes().first() == Some(&b'/') {
        return Some(AT_FDCWD_LINUX);
    }
    if dirfd == AT_FDCWD_LINUX {
        return Some(AT_FDCWD_LINUX);
    }
    table.get_lkl(dirfd)
}

fn host_open_and_addfd(
    listener_fd: RawFd,
    req: &libc::seccomp_notif,
    path: &CStr,
    flags: libc::c_long,
    mode: libc::c_long,
) -> SeccompDispatch {
    let host_fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            path.as_ptr(),
            flags as libc::c_int,
            mode as libc::mode_t,
        )
    };
    if host_fd < 0 {
        return seccomp_errno_reply(os_errno(libc::EIO));
    }
    let newfd_flags = if (flags & libc::O_CLOEXEC as libc::c_long) != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    let remote_fd = match notify_addfd(listener_fd, req.id, host_fd, newfd_flags) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = unsafe { libc::close(host_fd) };
            return seccomp_errno_reply(errno);
        }
    };
    let _ = unsafe { libc::close(host_fd) };
    seccomp_value_reply(remote_fd as i64)
}

fn host_openat2_and_addfd(
    listener_fd: RawFd,
    req: &libc::seccomp_notif,
    path: &CStr,
    how: &OpenHow,
) -> SeccompDispatch {
    let host_how = OpenHow {
        flags: how.flags,
        mode: how.mode,
        resolve: 0,
    };
    let mut host_fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            std::ptr::addr_of!(host_how),
            std::mem::size_of::<OpenHow>(),
        )
    } as libc::c_int;
    if host_fd < 0 {
        let errno = os_errno(libc::EIO);
        if errno == libc::ENOSYS {
            host_fd = unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    how.flags as libc::c_int,
                    how.mode as libc::mode_t,
                )
            };
            if host_fd < 0 {
                return seccomp_errno_reply(os_errno(libc::EIO));
            }
        } else {
            return seccomp_errno_reply(errno);
        }
    }
    let newfd_flags = if (how.flags & libc::O_CLOEXEC as u64) != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    let remote_fd = match notify_addfd(listener_fd, req.id, host_fd, newfd_flags) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = unsafe { libc::close(host_fd) };
            return seccomp_errno_reply(errno);
        }
    };
    let _ = unsafe { libc::close(host_fd) };
    seccomp_value_reply(remote_fd as i64)
}

fn forward_openat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &mut ForwardFdTable,
    host_root: Option<&Path>,
    listener_fd: RawFd,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let flags = to_c_long_arg(req.data.args[2]);
    let mode = to_c_long_arg(req.data.args[3]);
    if host_root.is_some() {
        if path.to_bytes().first() == Some(&b'/') && is_loader_runtime_path(path.as_c_str()) {
            return SeccompDispatch::Continue;
        }
        let host_path = match translate_path_for_host(pid, path.as_c_str(), dirfd_raw, host_root) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        return host_open_and_addfd(listener_fd, req, host_path.as_c_str(), flags, mode);
    }
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if is_lkl_virtual_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    if is_tty_like_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let ret = unsafe { lkl_sys_openat(sysnrs, lkl_dirfd, path.as_ptr(), flags, mode) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let fd = table.insert(ret, is_tty_like_path(path.as_c_str()));
    seccomp_value_reply(fd as i64)
}

fn forward_openat2(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &mut ForwardFdTable,
    host_root: Option<&Path>,
    listener_fd: RawFd,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let how = match read_remote_open_how(pid, req.data.args[2], req.data.args[3]) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if host_root.is_some() {
        if path.to_bytes().first() == Some(&b'/') && is_loader_runtime_path(path.as_c_str()) {
            return SeccompDispatch::Continue;
        }
        let host_path = match translate_path_for_host(pid, path.as_c_str(), dirfd_raw, host_root) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        return host_openat2_and_addfd(listener_fd, req, host_path.as_c_str(), &how);
    }
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if is_lkl_virtual_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    if is_tty_like_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let mut ret = unsafe {
        lkl_sys_openat2(
            sysnrs,
            lkl_dirfd,
            path.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<OpenHow>() as libc::c_long,
        )
    };
    if ret == -libc::ENOSYS as libc::c_long {
        if how.resolve != 0 {
            return seccomp_errno_reply(libc::EOPNOTSUPP);
        }
        ret = unsafe { lkl_sys_openat(sysnrs, lkl_dirfd, path.as_ptr(), how.flags as libc::c_long, how.mode as libc::c_long) };
    }
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let fd = table.insert(ret, is_tty_like_path(path.as_c_str()));
    seccomp_value_reply(fd as i64)
}

fn forward_open_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &mut ForwardFdTable,
    host_root: Option<&Path>,
    listener_fd: RawFd,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let flags = to_c_long_arg(req.data.args[1]);
    let mode = to_c_long_arg(req.data.args[2]);
    if host_root.is_some() {
        if path.to_bytes().first() == Some(&b'/') && is_loader_runtime_path(path.as_c_str()) {
            return SeccompDispatch::Continue;
        }
        let host_path = match translate_path_for_host(pid, path.as_c_str(), AT_FDCWD_LINUX, host_root) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        return host_open_and_addfd(listener_fd, req, host_path.as_c_str(), flags, mode);
    }
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if is_lkl_virtual_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    if is_tty_like_path(path.as_c_str()) {
        return SeccompDispatch::Continue;
    }
    let ret = unsafe { lkl_sys_openat(sysnrs, AT_FDCWD_LINUX, path.as_ptr(), flags, mode) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let fd = table.insert(ret, is_tty_like_path(path.as_c_str()));
    seccomp_value_reply(fd as i64)
}

fn forward_fstat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    _normalize: bool,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let remote_stat = req.data.args[1];
    if remote_stat == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let ret = unsafe { lkl_sys_fstat(sysnrs, lkl_fd, stat_buf.as_mut_ptr().cast::<c_void>()) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let stat_bytes = unsafe {
        std::slice::from_raw_parts(
            stat_buf.as_ptr().cast::<u8>(),
            std::mem::size_of::<libc::stat>(),
        )
    };
    let pid = req.pid as libc::pid_t;
    if let Err(errno) = process_vm_write_exact(pid, remote_stat, stat_bytes) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(0)
}

fn forward_newfstatat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
    normalize: bool,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let remote_stat = req.data.args[2];
    if remote_stat == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let flags = to_c_long_arg(req.data.args[3]);
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let ret = if path.to_bytes().is_empty() && (flags & libc::AT_EMPTY_PATH as libc::c_long) != 0 {
        unsafe { lkl_sys_fstat(sysnrs, lkl_dirfd, stat_buf.as_mut_ptr().cast::<c_void>()) }
    } else {
        unsafe {
            lkl_sys_newfstatat(
                sysnrs,
                lkl_dirfd,
                path.as_ptr(),
                stat_buf.as_mut_ptr().cast::<c_void>(),
                flags,
            )
        }
    };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    
    // Apply normalization if enabled
    if normalize {
        unsafe {
            let stat_ref = stat_buf.assume_init_mut();
            if let Some((mode, uid, gid)) = normalized_permissions(path.as_c_str()) {
                stat_ref.st_mode = (stat_ref.st_mode & libc::S_IFMT) | (mode & !libc::S_IFMT);
                stat_ref.st_uid = uid;
                stat_ref.st_gid = gid;
            }
        }
    }
    
    let stat_bytes = unsafe {
        std::slice::from_raw_parts(
            stat_buf.as_ptr().cast::<u8>(),
            std::mem::size_of::<libc::stat>(),
        )
    };
    if let Err(errno) = process_vm_write_exact(pid, remote_stat, stat_bytes) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(0)
}

fn forward_statx(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
    normalize: bool,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let flags = to_c_long_arg(req.data.args[2]) as libc::c_int;
    let mask = to_c_long_arg(req.data.args[3]) as libc::c_uint;
    let remote_statx = req.data.args[4];
    if remote_statx == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    
    // Allocate buffer for statx struct (0x100 bytes is typically enough)
    let mut statx_buf = vec![0u8; 0x100];
    let ret = unsafe {
        lkl_sys_statx(
            sysnrs,
            lkl_dirfd,
            path.as_ptr(),
            flags,
            mask,
            statx_buf.as_mut_ptr() as *mut c_void,
        )
    };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    
    // Apply normalization if enabled
    if normalize {
        if let Some((mode, uid, gid)) = normalized_permissions(path.as_c_str()) {
            // statx struct layout: stx_mode at offset 0x20, stx_uid at 0x48, stx_gid at 0x4c
            // These offsets may vary by architecture, but are standard on x86_64
            if statx_buf.len() >= 0x50 {
                let mode_le = mode as u16;
                statx_buf[0x20..0x22].copy_from_slice(&mode_le.to_le_bytes());
                let uid_le = uid as u32;
                statx_buf[0x48..0x4c].copy_from_slice(&uid_le.to_le_bytes());
                let gid_le = gid as u32;
                statx_buf[0x4c..0x50].copy_from_slice(&gid_le.to_le_bytes());
            }
        }
    }
    
    if let Err(errno) = process_vm_write_exact(pid, remote_statx, &statx_buf) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(0)
}

fn forward_faccessat2(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let mode = to_c_long_arg(req.data.args[2]);
    let flags = to_c_long_arg(req.data.args[3]);
    let ret = unsafe { lkl_sys_faccessat2(sysnrs, lkl_dirfd, path.as_ptr(), mode, flags) };
    seccomp_from_lkl_ret(ret)
}

fn forward_read_like(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    is_pread: bool,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    if fd == libc::STDIN_FILENO as libc::c_long
        || fd == libc::STDOUT_FILENO as libc::c_long
        || fd == libc::STDERR_FILENO as libc::c_long
    {
        return SeccompDispatch::Continue;
    }
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let remote_buf = req.data.args[1];
    let count = match to_usize_arg(req.data.args[2]) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if remote_buf == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    if count == 0 {
        return seccomp_value_reply(0);
    }
    let pid = req.pid as libc::pid_t;
    let max_count = (libc::c_long::MAX as usize).min(1024 * 1024);
    let count = count.min(max_count);
    let mut total = 0usize;
    let mut scratch = vec![0u8; FORWARD_IO_CHUNK_LEN];
    while total < count {
        let chunk_len = scratch.len().min(count - total);
        let ret = if is_pread {
            let offset = to_c_long_arg(req.data.args[3]);
            unsafe {
                lkl_sys_pread64(
                    sysnrs,
                    lkl_fd,
                    scratch.as_mut_ptr().cast::<c_void>(),
                    chunk_len as libc::c_long,
                    offset + total as libc::c_long,
                )
            }
        } else {
            unsafe {
                lkl_sys_read(
                    sysnrs,
                    lkl_fd,
                    scratch.as_mut_ptr().cast::<c_void>(),
                    chunk_len as libc::c_long,
                )
            }
        };
        if ret < 0 {
            if total == 0 {
                return seccomp_errno_reply((-ret) as i32);
            }
            break;
        }
        let n = ret as usize;
        if n == 0 {
            break;
        }
        let remote = match add_remote_ptr(remote_buf, total) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        if let Err(errno) = process_vm_write_exact(pid, remote, &scratch[..n]) {
            return seccomp_errno_reply(errno);
        }
        total += n;
        if n < chunk_len {
            break;
        }
    }
    seccomp_value_reply(total as i64)
}

fn forward_write(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    if fd == libc::STDIN_FILENO as libc::c_long
        || fd == libc::STDOUT_FILENO as libc::c_long
        || fd == libc::STDERR_FILENO as libc::c_long
    {
        return SeccompDispatch::Continue;
    }
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let mirror_host_stdio = fd == libc::STDOUT_FILENO as libc::c_long
        || fd == libc::STDERR_FILENO as libc::c_long
        || table.should_mirror_tty(fd);
    let remote_buf = req.data.args[1];
    let count = match to_usize_arg(req.data.args[2]) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if remote_buf == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    if count == 0 {
        return seccomp_value_reply(0);
    }
    let pid = req.pid as libc::pid_t;
    let max_count = (libc::c_long::MAX as usize).min(1024 * 1024);
    let count = count.min(max_count);
    let mut total = 0usize;
    let mut scratch = vec![0u8; FORWARD_IO_CHUNK_LEN];
    while total < count {
        let chunk_len = scratch.len().min(count - total);
        let remote = match add_remote_ptr(remote_buf, total) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        if let Err(errno) = process_vm_read_exact(pid, remote, &mut scratch[..chunk_len]) {
            return seccomp_errno_reply(errno);
        }
        let ret = unsafe {
            lkl_sys_write(
                sysnrs,
                lkl_fd,
                scratch.as_ptr().cast::<c_void>(),
                chunk_len as libc::c_long,
            )
        };
        if ret < 0 {
            if total == 0 {
                return seccomp_errno_reply((-ret) as i32);
            }
            break;
        }
        let n = ret as usize;
        if mirror_host_stdio && n > 0 {
            let _ = unsafe {
                libc::write(
                    fd as libc::c_int,
                    scratch.as_ptr().cast::<c_void>(),
                    n,
                )
            };
        }
        total += n;
        if n < chunk_len {
            break;
        }
    }
    seccomp_value_reply(total as i64)
}

fn forward_lseek(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &ForwardFdTable) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let off = to_c_long_arg(req.data.args[1]);
    let whence = to_c_long_arg(req.data.args[2]);
    let ret = unsafe { lkl_sys_lseek(sysnrs, lkl_fd, off, whence) };
    seccomp_from_lkl_ret(ret)
}

fn forward_getdents64(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let remote_dirp = req.data.args[1];
    let count = match to_usize_arg(req.data.args[2]) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if count == 0 {
        return seccomp_value_reply(0);
    }
    if remote_dirp == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let max_count = (libc::c_long::MAX as usize).min(1024 * 1024);
    let count = count.min(max_count);
    if count < std::mem::size_of::<libc::dirent64>() {
        return seccomp_errno_reply(libc::EINVAL);
    }
    let mut buf = vec![0u8; count];
    let ret = unsafe {
        lkl_sys_getdents64(
            sysnrs,
            lkl_fd,
            buf.as_mut_ptr().cast::<c_void>(),
            count as libc::c_long,
        )
    };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let n = ret as usize;
    if n > buf.len() {
        return seccomp_errno_reply(libc::EIO);
    }
    let pid = req.pid as libc::pid_t;
    if let Err(errno) = process_vm_write_exact(pid, remote_dirp, &buf[..n]) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(n as i64)
}

fn forward_getdents(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let remote_dirp = req.data.args[1];
    let count = match to_usize_arg(req.data.args[2]) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if count == 0 {
        return seccomp_value_reply(0);
    }
    if remote_dirp == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let max_count = (libc::c_long::MAX as usize).min(1024 * 1024);
    let count = count.min(max_count);
    if count < std::mem::size_of::<libc::dirent>() {
        return seccomp_errno_reply(libc::EINVAL);
    }
    let mut buf = vec![0u8; count];
    let ret = unsafe {
        lkl_sys_getdents(
            sysnrs,
            lkl_fd,
            buf.as_mut_ptr().cast::<c_void>(),
            count as libc::c_long,
        )
    };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let n = ret as usize;
    if n > buf.len() {
        return seccomp_errno_reply(libc::EIO);
    }
    let pid = req.pid as libc::pid_t;
    if let Err(errno) = process_vm_write_exact(pid, remote_dirp, &buf[..n]) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(n as i64)
}

fn forward_close(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &mut ForwardFdTable) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let ret = unsafe { lkl_sys_close(sysnrs, lkl_fd) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let _ = table.remove(fd);
    seccomp_value_reply(0)
}

fn forward_fcntl(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &mut ForwardFdTable) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let cmd = to_c_long_arg(req.data.args[1]);
    let arg = to_c_long_arg(req.data.args[2]);
    if cmd == libc::F_DUPFD as libc::c_long || cmd == libc::F_DUPFD_CLOEXEC as libc::c_long {
        let ret = unsafe { lkl_sys_fcntl(sysnrs, lkl_fd, cmd, arg) };
        if ret < 0 {
            return seccomp_errno_reply((-ret) as i32);
        }
        let mut new_fd = table.next_fd.max(arg.max(0));
        while table.lkl_by_forward_fd.contains_key(&new_fd) {
            new_fd += 1;
        }
        let mirror_tty = table.should_mirror_tty(fd);
        table.insert_at(new_fd, ret, mirror_tty);
        return seccomp_value_reply(new_fd as i64);
    }
    let ret = unsafe { lkl_sys_fcntl(sysnrs, lkl_fd, cmd, arg) };
    seccomp_from_lkl_ret(ret)
}

fn forward_dup(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &mut ForwardFdTable) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let ret = unsafe { lkl_sys_dup(sysnrs, lkl_fd) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let mirror_tty = table.should_mirror_tty(fd);
    let newfd = table.insert(ret, mirror_tty);
    seccomp_value_reply(newfd as i64)
}

fn forward_dup2(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &mut ForwardFdTable) -> SeccompDispatch {
    let oldfd = to_c_long_arg(req.data.args[0]);
    let newfd = to_c_long_arg(req.data.args[1]);
    let Some(lkl_old) = table.get_lkl(oldfd) else {
        return SeccompDispatch::Continue;
    };
    if oldfd == newfd {
        return seccomp_value_reply(newfd as i64);
    }
    if let Some(old) = table.remove(newfd) {
        let _ = unsafe { lkl_sys_close(sysnrs, old) };
    }
    let ret = unsafe { lkl_sys_dup(sysnrs, lkl_old) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let mirror_tty = table.should_mirror_tty(oldfd);
    table.insert_at(newfd, ret, mirror_tty);
    seccomp_value_reply(newfd as i64)
}

fn forward_dup3(req: &libc::seccomp_notif, sysnrs: &SysNrs, table: &mut ForwardFdTable) -> SeccompDispatch {
    let oldfd = to_c_long_arg(req.data.args[0]);
    let newfd = to_c_long_arg(req.data.args[1]);
    let flags = to_c_long_arg(req.data.args[2]);
    let Some(lkl_old) = table.get_lkl(oldfd) else {
        return SeccompDispatch::Continue;
    };
    if oldfd == newfd {
        return seccomp_errno_reply(libc::EINVAL);
    }
    if let Some(old) = table.remove(newfd) {
        let _ = unsafe { lkl_sys_close(sysnrs, old) };
    }
    let ret = unsafe { lkl_sys_dup3(sysnrs, lkl_old, newfd, flags) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let mirror_tty = table.should_mirror_tty(oldfd);
    table.insert_at(newfd, ret, mirror_tty);
    seccomp_value_reply(newfd as i64)
}

fn forward_chdir(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    if host_root.is_some() {
        // Rooted mode keeps host cwd authoritative; validate first to block escapes.
        if path.to_bytes().first() == Some(&b'/') {
            let target_host = match translate_path_for_host(pid, path.as_c_str(), AT_FDCWD_LINUX, host_root) {
                Ok(v) => v,
                Err(errno) => return seccomp_errno_reply(errno),
            };
            if !is_lkl_virtual_path(target_host.as_c_str()) {
                let cwd = match read_proc_cwd(pid) {
                    Ok(v) => v,
                    Err(errno) => return seccomp_errno_reply(errno),
                };
                let target_path = Path::new(std::ffi::OsStr::from_bytes(target_host.to_bytes()));
                let rel = relative_path(&cwd, target_path);
                let rel_bytes = rel.as_os_str().as_bytes().to_vec();
                if rel_bytes.len() > path.to_bytes().len() {
                    return seccomp_errno_reply(libc::ENAMETOOLONG);
                }
                let mut encoded = rel_bytes;
                encoded.push(0);
                if let Err(errno) = process_vm_write_exact(pid, req.data.args[0], &encoded) {
                    return seccomp_errno_reply(errno);
                }
            }
            return SeccompDispatch::Continue;
        }
        if let Err(errno) = translate_path_for_host(pid, path.as_c_str(), AT_FDCWD_LINUX, host_root) {
            return seccomp_errno_reply(errno);
        }
        return SeccompDispatch::Continue;
    }
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let ret = unsafe { lkl_sys_chdir(sysnrs, path.as_ptr()) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let _ = host_root;
    seccomp_value_reply(0)
}

fn forward_fchdir(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
) -> SeccompDispatch {
    let fd = to_c_long_arg(req.data.args[0]);
    let Some(lkl_fd) = table.get_lkl(fd) else {
        return SeccompDispatch::Continue;
    };
    let ret = unsafe { lkl_sys_fchdir(sysnrs, lkl_fd) };
    seccomp_from_lkl_ret(ret)
}

fn forward_getcwd(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let remote_buf = req.data.args[0];
    let size = to_usize_arg(req.data.args[1]).unwrap_or(0);
    if remote_buf == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    if size == 0 {
        return seccomp_errno_reply(libc::EINVAL);
    }
    if let Some(root) = host_root {
        let cwd = match read_proc_cwd(pid) {
            Ok(v) => v,
            Err(errno) => return seccomp_errno_reply(errno),
        };
        let mut path = guest_path_from_host(&cwd, root)
            .unwrap_or_else(|| cwd.to_string_lossy().into_owned())
            .into_bytes();
        path.push(0);
        if path.len() > size {
            return seccomp_errno_reply(libc::ERANGE);
        }
        if let Err(errno) = process_vm_write_exact(pid, remote_buf, &path) {
            return seccomp_errno_reply(errno);
        }
        return seccomp_value_reply(path.len() as i64);
    }
    let max_size = (libc::c_long::MAX as usize).min(FORWARD_MAX_PATH_LEN);
    let size = size.min(max_size);
    let mut out = vec![0u8; size];
    let ret = unsafe { lkl_sys_getcwd(sysnrs, out.as_mut_ptr().cast::<libc::c_char>(), size as libc::c_long) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    let n = ret as usize;
    if n == 0 || n > out.len() {
        return seccomp_errno_reply(libc::EIO);
    }
    if let Err(errno) = process_vm_write_exact(pid, remote_buf, &out[..n]) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(n as i64)
}

fn forward_stat_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    nofollow: bool,
    host_root: Option<&Path>,
    normalize: bool,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let remote_stat = req.data.args[1];
    if remote_stat == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let flags = if nofollow { libc::AT_SYMLINK_NOFOLLOW as libc::c_long } else { 0 };
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let ret = unsafe {
        lkl_sys_newfstatat(
            sysnrs,
            AT_FDCWD_LINUX,
            path.as_ptr(),
            stat_buf.as_mut_ptr().cast::<c_void>(),
            flags,
        )
    };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    
    // Apply normalization if enabled
    if normalize {
        unsafe {
            let stat_ref = stat_buf.assume_init_mut();
            if let Some((mode, uid, gid)) = normalized_permissions(path.as_c_str()) {
                stat_ref.st_mode = (stat_ref.st_mode & libc::S_IFMT) | (mode & !libc::S_IFMT);
                stat_ref.st_uid = uid;
                stat_ref.st_gid = gid;
            }
        }
    }
    
    let stat_bytes = unsafe {
        std::slice::from_raw_parts(
            stat_buf.as_ptr().cast::<u8>(),
            std::mem::size_of::<libc::stat>(),
        )
    };
    if let Err(errno) = process_vm_write_exact(pid, remote_stat, stat_bytes) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(0)
}

fn forward_access_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let mode = to_c_long_arg(req.data.args[1]);
    let ret = unsafe { lkl_sys_faccessat2(sysnrs, AT_FDCWD_LINUX, path.as_ptr(), mode, 0) };
    seccomp_from_lkl_ret(ret)
}

fn forward_mkdir_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let mode = to_c_long_arg(req.data.args[1]);
    let ret = unsafe { lkl_sys_mkdir(sysnrs, path.as_ptr(), mode as libc::c_int) };
    seccomp_from_lkl_ret(ret)
}

fn forward_unlink_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let ret = unsafe { lkl_sys_unlinkat(sysnrs, AT_FDCWD_LINUX, path.as_ptr(), 0) };
    seccomp_from_lkl_ret(ret)
}

fn forward_rmdir_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let ret = unsafe {
        lkl_sys_unlinkat(
            sysnrs,
            AT_FDCWD_LINUX,
            path.as_ptr(),
            libc::AT_REMOVEDIR as libc::c_long,
        )
    };
    seccomp_from_lkl_ret(ret)
}

fn forward_rename_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let oldpath = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let newpath = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let oldpath = match translate_path_for_lkl(pid, oldpath.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let newpath = match translate_path_for_lkl(pid, newpath.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let ret = unsafe {
        lkl_sys_renameat2(
            sysnrs,
            AT_FDCWD_LINUX,
            oldpath.as_ptr(),
            AT_FDCWD_LINUX,
            newpath.as_ptr(),
            0,
        )
    };
    seccomp_from_lkl_ret(ret)
}

fn forward_chmod_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let mode = to_c_long_arg(req.data.args[1]);
    let ret = unsafe { lkl_sys_fchmodat(sysnrs, AT_FDCWD_LINUX, path.as_ptr(), mode, 0) };
    seccomp_from_lkl_ret(ret)
}

fn forward_chown_legacy(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let path = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let owner = to_c_long_arg(req.data.args[1]);
    let group = to_c_long_arg(req.data.args[2]);
    let ret = unsafe { lkl_sys_fchownat(sysnrs, AT_FDCWD_LINUX, path.as_ptr(), owner, group, 0) };
    seccomp_from_lkl_ret(ret)
}

fn forward_mkdirat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let mode = to_c_long_arg(req.data.args[2]);
    let ret = unsafe { lkl_sys_mkdirat(sysnrs, lkl_dirfd, path.as_ptr(), mode) };
    seccomp_from_lkl_ret(ret)
}

fn forward_unlinkat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let flags = to_c_long_arg(req.data.args[2]);
    let ret = unsafe { lkl_sys_unlinkat(sysnrs, lkl_dirfd, path.as_ptr(), flags) };
    seccomp_from_lkl_ret(ret)
}

fn forward_renameat2(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let olddirfd_raw = to_dirfd_arg(req.data.args[0]);
    let oldpath = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let newdirfd_raw = to_dirfd_arg(req.data.args[2]);
    let newpath = match read_remote_c_string(pid, req.data.args[3], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let oldpath = match translate_path_for_lkl(pid, oldpath.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let newpath = match translate_path_for_lkl(pid, newpath.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let olddirfd = match resolve_open_dirfd(oldpath.as_c_str(), olddirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let newdirfd = match resolve_open_dirfd(newpath.as_c_str(), newdirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let flags = to_c_long_arg(req.data.args[4]);
    let ret = unsafe {
        lkl_sys_renameat2(
            sysnrs,
            olddirfd,
            oldpath.as_ptr(),
            newdirfd,
            newpath.as_ptr(),
            flags,
        )
    };
    seccomp_from_lkl_ret(ret)
}

fn forward_fchmodat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let mode = to_c_long_arg(req.data.args[2]);
    let flags = to_c_long_arg(req.data.args[3]);
    let ret = unsafe { lkl_sys_fchmodat(sysnrs, lkl_dirfd, path.as_ptr(), mode, flags) };
    seccomp_from_lkl_ret(ret)
}

fn forward_fchownat(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &ForwardFdTable,
    host_root: Option<&Path>,
) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let dirfd_raw = to_dirfd_arg(req.data.args[0]);
    let path = match read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let path = match translate_path_for_lkl(pid, path.as_c_str(), host_root) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let lkl_dirfd = match resolve_open_dirfd(path.as_c_str(), dirfd_raw, table) {
        Some(v) => v,
        None => return SeccompDispatch::Continue,
    };
    let owner = to_c_long_arg(req.data.args[2]);
    let group = to_c_long_arg(req.data.args[3]);
    let flags = to_c_long_arg(req.data.args[4]);
    let ret = unsafe { lkl_sys_fchownat(sysnrs, lkl_dirfd, path.as_ptr(), owner, group, flags) };
    seccomp_from_lkl_ret(ret)
}

fn forward_mount(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let source = if req.data.args[0] == 0 {
        None
    } else {
        Some(read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN))
    };
    let target = read_remote_c_string(pid, req.data.args[1], FORWARD_MAX_PATH_LEN);
    let fstype = if req.data.args[2] == 0 {
        None
    } else {
        Some(read_remote_c_string(pid, req.data.args[2], FORWARD_MAX_PATH_LEN))
    };
    let flags = to_c_long_arg(req.data.args[3]);
    let data_ptr = req.data.args[4];
    let source = match source {
        None => None,
        Some(Ok(v)) => Some(v),
        Some(Err(errno)) => return seccomp_errno_reply(errno),
    };
    let target = match target {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let fstype = match fstype {
        None => None,
        Some(Ok(v)) => Some(v),
        Some(Err(errno)) => return seccomp_errno_reply(errno),
    };
    let data = if data_ptr == 0 {
        None
    } else {
        match read_remote_c_string(pid, data_ptr, FORWARD_MAX_PATH_LEN) {
            Ok(v) => Some(v),
            Err(errno) => return seccomp_errno_reply(errno),
        }
    };
    let ret = unsafe {
        lkl_sys_mount(
            sysnrs,
            source
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            target.as_ptr(),
            fstype
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            data
                .as_ref()
                .map(|v| v.as_ptr() as *const c_void)
                .unwrap_or(std::ptr::null()),
        )
    };
    seccomp_from_lkl_ret(ret)
}

fn forward_umount2(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let target = match read_remote_c_string(pid, req.data.args[0], FORWARD_MAX_PATH_LEN) {
        Ok(v) => v,
        Err(errno) => return seccomp_errno_reply(errno),
    };
    let flags = to_c_long_arg(req.data.args[1]);
    let ret = unsafe { lkl_sys_umount2(sysnrs, target.as_ptr(), flags) };
    seccomp_from_lkl_ret(ret)
}

fn forward_getuid(sysnrs: &SysNrs) -> SeccompDispatch {
    seccomp_from_lkl_ret(unsafe { lkl_sys_getuid(sysnrs) })
}
fn forward_getuid_override(uid: libc::uid_t) -> SeccompDispatch {
    seccomp_value_reply(uid as i64)
}
fn forward_geteuid(sysnrs: &SysNrs) -> SeccompDispatch {
    seccomp_from_lkl_ret(unsafe { lkl_sys_geteuid(sysnrs) })
}
fn forward_geteuid_override(uid: libc::uid_t) -> SeccompDispatch {
    seccomp_value_reply(uid as i64)
}
fn forward_getresuid_override(req: &libc::seccomp_notif, uid: libc::uid_t) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    for ptr in [req.data.args[0], req.data.args[1], req.data.args[2]] {
        if ptr != 0 && process_vm_write_exact(pid, ptr, &uid.to_ne_bytes()).is_err() {
            return seccomp_errno_reply(libc::EIO);
        }
    }
    seccomp_value_reply(0)
}
fn forward_getresuid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let ruid = req.data.args[0];
    let euid = req.data.args[1];
    let suid = req.data.args[2];
    if ruid != 0 {
        let val = unsafe { lkl_sys_getuid(sysnrs) } as libc::uid_t;
        if let Err(errno) = process_vm_write_exact(pid, ruid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    if euid != 0 {
        let val = unsafe { lkl_sys_geteuid(sysnrs) } as libc::uid_t;
        if let Err(errno) = process_vm_write_exact(pid, euid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    if suid != 0 {
        let val = unsafe { lkl_sys_geteuid(sysnrs) } as libc::uid_t;
        if let Err(errno) = process_vm_write_exact(pid, suid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    seccomp_value_reply(0)
}
fn forward_getgid(sysnrs: &SysNrs) -> SeccompDispatch {
    seccomp_from_lkl_ret(unsafe { lkl_sys_getgid(sysnrs) })
}
fn forward_getgid_override(gid: libc::gid_t) -> SeccompDispatch {
    seccomp_value_reply(gid as i64)
}
fn forward_getegid(sysnrs: &SysNrs) -> SeccompDispatch {
    seccomp_from_lkl_ret(unsafe { lkl_sys_getegid(sysnrs) })
}
fn forward_getegid_override(gid: libc::gid_t) -> SeccompDispatch {
    seccomp_value_reply(gid as i64)
}
fn forward_getresgid_override(req: &libc::seccomp_notif, gid: libc::gid_t) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    for ptr in [req.data.args[0], req.data.args[1], req.data.args[2]] {
        if ptr != 0 && process_vm_write_exact(pid, ptr, &gid.to_ne_bytes()).is_err() {
            return seccomp_errno_reply(libc::EIO);
        }
    }
    seccomp_value_reply(0)
}
fn forward_getgroups_override(req: &libc::seccomp_notif, gid: libc::gid_t) -> SeccompDispatch {
    let size = to_c_long_arg(req.data.args[0]);
    if size < 0 {
        return seccomp_errno_reply(libc::EINVAL);
    }
    if size == 0 {
        return seccomp_value_reply(1);
    }
    if size < 1 {
        return seccomp_errno_reply(libc::EINVAL);
    }
    let list = req.data.args[1];
    if list == 0 {
        return seccomp_errno_reply(libc::EFAULT);
    }
    let pid = req.pid as libc::pid_t;
    if let Err(errno) = process_vm_write_exact(pid, list, &gid.to_ne_bytes()) {
        return seccomp_errno_reply(errno);
    }
    seccomp_value_reply(1)
}
fn forward_getresgid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let pid = req.pid as libc::pid_t;
    let rgid = req.data.args[0];
    let egid = req.data.args[1];
    let sgid = req.data.args[2];
    if rgid != 0 {
        let val = unsafe { lkl_sys_getgid(sysnrs) } as libc::gid_t;
        if let Err(errno) = process_vm_write_exact(pid, rgid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    if egid != 0 {
        let val = unsafe { lkl_sys_getegid(sysnrs) } as libc::gid_t;
        if let Err(errno) = process_vm_write_exact(pid, egid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    if sgid != 0 {
        let val = unsafe { lkl_sys_getegid(sysnrs) } as libc::gid_t;
        if let Err(errno) = process_vm_write_exact(pid, sgid, &val.to_ne_bytes()) {
            return seccomp_errno_reply(errno);
        }
    }
    seccomp_value_reply(0)
}
fn forward_getgroups(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let size = to_c_long_arg(req.data.args[0]);
    let list = req.data.args[1];
    if size < 0 {
        return seccomp_errno_reply(libc::EINVAL);
    }
    let count = unsafe { lkl_sys_getgroups(sysnrs, size, std::ptr::null_mut()) };
    if count < 0 {
        return seccomp_errno_reply((-count) as i32);
    }
    if size == 0 {
        return seccomp_value_reply(count as i64);
    }
    let mut buf = vec![0u8; (count as usize).saturating_mul(std::mem::size_of::<libc::gid_t>())];
    let ret = unsafe { lkl_sys_getgroups(sysnrs, count, buf.as_mut_ptr().cast::<libc::gid_t>()) };
    if ret < 0 {
        return seccomp_errno_reply((-ret) as i32);
    }
    if list != 0 {
        let pid = req.pid as libc::pid_t;
        if let Err(errno) = process_vm_write_exact(pid, list, &buf) {
            return seccomp_errno_reply(errno);
        }
    }
    seccomp_value_reply(ret as i64)
}
fn forward_setuid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let uid = to_c_long_arg(req.data.args[0]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setuid(sysnrs, uid) })
}
fn forward_setreuid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let ruid = to_c_long_arg(req.data.args[0]);
    let euid = to_c_long_arg(req.data.args[1]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setreuid(sysnrs, ruid, euid) })
}
fn forward_setresuid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let ruid = to_c_long_arg(req.data.args[0]);
    let euid = to_c_long_arg(req.data.args[1]);
    let suid = to_c_long_arg(req.data.args[2]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setresuid(sysnrs, ruid, euid, suid) })
}
fn forward_setgid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let gid = to_c_long_arg(req.data.args[0]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setgid(sysnrs, gid) })
}
fn forward_setregid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let rgid = to_c_long_arg(req.data.args[0]);
    let egid = to_c_long_arg(req.data.args[1]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setregid(sysnrs, rgid, egid) })
}
fn forward_setresgid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let rgid = to_c_long_arg(req.data.args[0]);
    let egid = to_c_long_arg(req.data.args[1]);
    let sgid = to_c_long_arg(req.data.args[2]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setresgid(sysnrs, rgid, egid, sgid) })
}
fn forward_setgroups(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let size = to_c_long_arg(req.data.args[0]);
    let list = req.data.args[1];
    if size < 0 {
        return seccomp_errno_reply(libc::EINVAL);
    }
    if size == 0 {
        return seccomp_from_lkl_ret(unsafe { lkl_sys_setgroups(sysnrs, 0, std::ptr::null()) });
    }
    let byte_len = (size as usize).saturating_mul(std::mem::size_of::<libc::gid_t>());
    let mut buf = vec![0u8; byte_len];
    let pid = req.pid as libc::pid_t;
    if let Err(errno) = process_vm_read_exact(pid, list, &mut buf) {
        return seccomp_errno_reply(errno);
    }
    let ret = unsafe { lkl_sys_setgroups(sysnrs, size, buf.as_ptr().cast::<libc::gid_t>()) };
    seccomp_from_lkl_ret(ret)
}
fn forward_setfsgid(req: &libc::seccomp_notif, sysnrs: &SysNrs) -> SeccompDispatch {
    let gid = to_c_long_arg(req.data.args[0]);
    seccomp_from_lkl_ret(unsafe { lkl_sys_setfsgid(sysnrs, gid) })
}

fn dispatch_forward_syscall(
    req: &libc::seccomp_notif,
    sysnrs: &SysNrs,
    table: &mut ForwardFdTable,
    host_root: Option<&Path>,
    verbose: bool,
    listener_fd: RawFd,
    root_identity: bool,
    id_override: Option<(libc::uid_t, libc::gid_t)>,
    normalize: bool,
) -> SeccompDispatch {
    let nr = req.data.nr;
    if verbose {
        eprintln!("seccomp notify: pid={} nr={} ({})", req.pid, nr, syscall_name_from_nr(nr));
    }
    match nr {
        HOST_NR_STAT => forward_stat_legacy(req, sysnrs, false, host_root, normalize),
        HOST_NR_LSTAT => forward_stat_legacy(req, sysnrs, true, host_root, normalize),
        HOST_NR_ACCESS => forward_access_legacy(req, sysnrs, host_root),
        HOST_NR_MKDIR => forward_mkdir_legacy(req, sysnrs, host_root),
        HOST_NR_RMDIR => forward_rmdir_legacy(req, sysnrs, host_root),
        HOST_NR_UNLINK => forward_unlink_legacy(req, sysnrs, host_root),
        HOST_NR_RENAME => forward_rename_legacy(req, sysnrs, host_root),
        HOST_NR_CHMOD => forward_chmod_legacy(req, sysnrs, host_root),
        HOST_NR_CHOWN => forward_chown_legacy(req, sysnrs, host_root),
        HOST_NR_OPEN => forward_open_legacy(req, sysnrs, table, host_root, listener_fd),
        HOST_NR_OPENAT => forward_openat(req, sysnrs, table, host_root, listener_fd),
        HOST_NR_OPENAT2 => forward_openat2(req, sysnrs, table, host_root, listener_fd),
        HOST_NR_FSTAT => forward_fstat(req, sysnrs, table, normalize),
        HOST_NR_NEWFSTATAT => forward_newfstatat(req, sysnrs, table, host_root, normalize),
        HOST_NR_STATX => forward_statx(req, sysnrs, table, host_root, normalize),
        HOST_NR_FACCESSAT2 => forward_faccessat2(req, sysnrs, table, host_root),
        HOST_NR_GETDENTS64 => forward_getdents64(req, sysnrs, table),
        HOST_NR_GETDENTS => forward_getdents(req, sysnrs, table),
        HOST_NR_MKDIRAT => forward_mkdirat(req, sysnrs, table, host_root),
        HOST_NR_UNLINKAT => forward_unlinkat(req, sysnrs, table, host_root),
        HOST_NR_RENAMEAT2 => forward_renameat2(req, sysnrs, table, host_root),
        HOST_NR_FCHMODAT => forward_fchmodat(req, sysnrs, table, host_root),
        HOST_NR_FCHOWNAT => forward_fchownat(req, sysnrs, table, host_root),
        HOST_NR_CHDIR => forward_chdir(req, sysnrs, host_root),
        HOST_NR_FCHDIR => forward_fchdir(req, sysnrs, table),
        HOST_NR_GETCWD => forward_getcwd(req, sysnrs, host_root),
        HOST_NR_GETUID if host_root.is_some() && root_identity => forward_getuid_override(0),
        HOST_NR_GETUID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETUID if host_root.is_some() && !root_identity => {
            let (uid, _) = id_override.unwrap();
            forward_getuid_override(uid)
        }
        HOST_NR_GETUID => forward_getuid(sysnrs),
        HOST_NR_GETEUID if host_root.is_some() && root_identity => forward_geteuid_override(0),
        HOST_NR_GETEUID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETEUID if host_root.is_some() && !root_identity => {
            let (uid, _) = id_override.unwrap();
            forward_geteuid_override(uid)
        }
        HOST_NR_GETEUID => forward_geteuid(sysnrs),
        HOST_NR_GETRESUID if host_root.is_some() && root_identity => forward_getresuid_override(req, 0),
        HOST_NR_GETRESUID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETRESUID if host_root.is_some() && !root_identity => {
            let (uid, _) = id_override.unwrap();
            forward_getresuid_override(req, uid)
        }
        HOST_NR_GETRESUID => forward_getresuid(req, sysnrs),
        HOST_NR_GETGID if host_root.is_some() && root_identity => forward_getgid_override(0),
        HOST_NR_GETGID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETGID if host_root.is_some() && !root_identity => {
            let (_, gid) = id_override.unwrap();
            forward_getgid_override(gid)
        }
        HOST_NR_GETGID => forward_getgid(sysnrs),
        HOST_NR_GETEGID if host_root.is_some() && root_identity => forward_getegid_override(0),
        HOST_NR_GETEGID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETEGID if host_root.is_some() && !root_identity => {
            let (_, gid) = id_override.unwrap();
            forward_getegid_override(gid)
        }
        HOST_NR_GETEGID => forward_getegid(sysnrs),
        HOST_NR_GETRESGID if host_root.is_some() && root_identity => forward_getresgid_override(req, 0),
        HOST_NR_GETRESGID if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETRESGID if host_root.is_some() && !root_identity => {
            let (_, gid) = id_override.unwrap();
            forward_getresgid_override(req, gid)
        }
        HOST_NR_GETRESGID => forward_getresgid(req, sysnrs),
        HOST_NR_GETGROUPS if host_root.is_some() && root_identity => forward_getgroups_override(req, 0),
        HOST_NR_GETGROUPS if host_root.is_some() && !root_identity && id_override.is_none() => SeccompDispatch::Continue,
        HOST_NR_GETGROUPS if host_root.is_some() && !root_identity => {
            let (_, gid) = id_override.unwrap();
            forward_getgroups_override(req, gid)
        }
        HOST_NR_GETGROUPS => forward_getgroups(req, sysnrs),
        HOST_NR_SETUID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETUID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETUID => forward_setuid(req, sysnrs),
        HOST_NR_SETREUID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETREUID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETREUID => forward_setreuid(req, sysnrs),
        HOST_NR_SETRESUID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETRESUID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETRESUID => forward_setresuid(req, sysnrs),
        HOST_NR_SETGID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETGID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETGID => forward_setgid(req, sysnrs),
        HOST_NR_SETREGID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETREGID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETREGID => forward_setregid(req, sysnrs),
        HOST_NR_SETRESGID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETRESGID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETRESGID => forward_setresgid(req, sysnrs),
        HOST_NR_SETGROUPS if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETGROUPS if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETGROUPS => forward_setgroups(req, sysnrs),
        HOST_NR_SETFSGID if host_root.is_some() && root_identity => seccomp_value_reply(0),
        HOST_NR_SETFSGID if host_root.is_some() && !root_identity => SeccompDispatch::Continue,
        HOST_NR_SETFSGID => forward_setfsgid(req, sysnrs),
        HOST_NR_MOUNT => forward_mount(req, sysnrs),
        HOST_NR_UMOUNT2 => forward_umount2(req, sysnrs),
        HOST_NR_CLOSE => forward_close(req, sysnrs, table),
        HOST_NR_FCNTL => forward_fcntl(req, sysnrs, table),
        HOST_NR_DUP => forward_dup(req, sysnrs, table),
        HOST_NR_DUP2 => forward_dup2(req, sysnrs, table),
        HOST_NR_DUP3 => forward_dup3(req, sysnrs, table),
        HOST_NR_READ => forward_read_like(req, sysnrs, table, false),
        HOST_NR_PREAD64 => forward_read_like(req, sysnrs, table, true),
        HOST_NR_WRITE => forward_write(req, sysnrs, table),
        HOST_NR_LSEEK => forward_lseek(req, sysnrs, table),
        HOST_NR_SOCKET => {
            let domain = to_c_long_arg(req.data.args[0]);
            let sock_type = to_c_long_arg(req.data.args[1]);
            let protocol = to_c_long_arg(req.data.args[2]);
            let ret = unsafe { lkl_sys_socket(sysnrs, domain, sock_type, protocol) };
            if ret < 0 {
                seccomp_errno_reply((-ret) as i32)
            } else {
                let fd = table.insert(ret, false);
                seccomp_value_reply(fd as i64)
            }
        }
        HOST_NR_CONNECT => {
            let fd = to_c_long_arg(req.data.args[0]);
            if let Some(lkl_fd) = table.get_lkl(fd) {
                let pid = req.pid as libc::pid_t;
                let addr_ptr = req.data.args[1];
                let len = match to_usize_arg(req.data.args[2]) {
                    Ok(v) => v,
                    Err(errno) => return seccomp_errno_reply(errno),
                };
                if addr_ptr == 0 {
                    return seccomp_errno_reply(libc::EFAULT);
                }
                let mut buf = vec![0u8; len];
                if let Err(errno) = process_vm_read_exact(pid, addr_ptr, &mut buf) {
                    return seccomp_errno_reply(errno);
                }
                let ret = unsafe { lkl_syscall6(libc::SYS_connect as libc::c_long, lkl_fd, buf.as_ptr() as libc::c_long, len as libc::c_long, 0, 0, 0) };
                seccomp_from_lkl_ret(ret)
            } else {
                SeccompDispatch::Continue
            }
        }
        HOST_NR_EXECVE | HOST_NR_EXECVEAT => SeccompDispatch::Continue,
        _ => SeccompDispatch::Continue,
    }
}

fn notify_send(fd: RawFd, resp: &libc::seccomp_notif_resp) -> Result<(), String> {
    let ret = unsafe {
        libc::ioctl(
            fd,
            seccomp_ioctl_notif_send() as libc::c_ulong,
            resp as *const libc::seccomp_notif_resp,
        )
    };
    if ret < 0 {
        return Err(format!(
            "seccomp ioctl notify send failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn notify_recv(fd: RawFd, req: &mut libc::seccomp_notif) -> Result<(), String> {
    let ret = unsafe {
        libc::ioctl(
            fd,
            seccomp_ioctl_notif_recv() as libc::c_ulong,
            req as *mut libc::seccomp_notif,
        )
    };
    if ret < 0 {
        return Err(format!(
            "seccomp ioctl notify recv failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn notify_addfd(
    listener_fd: RawFd,
    id: u64,
    srcfd: RawFd,
    newfd_flags: u32,
) -> Result<libc::c_long, i32> {
    if srcfd < 0 {
        return Err(libc::EBADF);
    }
    let mut addfd = libc::seccomp_notif_addfd {
        id,
        flags: 0,
        srcfd: srcfd as u32,
        newfd: 0,
        newfd_flags,
    };
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            seccomp_ioctl_notif_addfd() as libc::c_ulong,
            &mut addfd as *mut libc::seccomp_notif_addfd,
        )
    };
    if ret < 0 {
        return Err(os_errno(libc::EIO));
    }
    Ok(ret as libc::c_long)
}

fn setup_ld_library_path(root: &Path) {
    use std::fs;
    
    let mut ld_lib_paths = vec![];
    
    // Standard library paths to check (relative to root)
    let standard_paths = vec![
        "lib64",
        "lib",
        "lib/x86_64-linux-gnu",
        "usr/lib64", 
        "usr/lib",
        "usr/lib/x86_64-linux-gnu",
        "usr/local/lib",
        "usr/libexec",
        "usr/libexec/sudo",
        "usr/libexec/coreutils",
    ];
    
    for lib_dir in standard_paths {
        let lib_path = root.join(lib_dir);
        if lib_path.exists() && lib_path.is_dir() {
            ld_lib_paths.push(lib_path.to_string_lossy().into_owned());
        }
    }
    
    // Also recursively check for other multiarch lib directories
    for base_dir in &["usr/lib", "lib"] {
        if let Ok(entries) = fs::read_dir(root.join(base_dir)) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_dir() {
                        let path = entry.path();
                        if let Some(file_name) = path.file_name() {
                            let name = file_name.to_string_lossy();
                            // Add any multiarch directories we haven't added yet
                            if (name.contains("x86_64") || name.contains("linux-gnu") 
                                || name.contains("aarch64") || name.contains("arm")) 
                                && !name.starts_with("x86_64-linux-gnu") 
                                && !name.starts_with("aarch64-linux-gnu") {
                                let path_str = path.to_string_lossy().into_owned();
                                if !ld_lib_paths.contains(&path_str) {
                                    ld_lib_paths.push(path_str);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if !ld_lib_paths.is_empty() {
        let ld_library_path = ld_lib_paths.join(":");
        if let Ok(ld_lib_c) = CString::new(ld_library_path) {
            let _ = unsafe { libc::setenv(c"LD_LIBRARY_PATH".as_ptr(), ld_lib_c.as_ptr(), 1) };
        }
    }
}

fn build_rpath_from_binary(binary_path: &Path, root: &Path) -> Option<String> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    
    let mut file = std::fs::File::open(binary_path).ok()?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    
    // Parse ELF header
    if n < 64 {
        return None;
    }
    
    // Check ELF magic
    if &buf[0..4] != b"\x7FELF" {
        return None;
    }
    
    // Get architecture flag (byte 4: 1=32-bit, 2=64-bit)
    let is_64bit = buf[4] == 2;
    if !is_64bit {
        return None;
    }
    
    // Get endianness (byte 5: 1=little, 2=big)
    let is_little_endian = buf[5] == 1;
    if !is_little_endian {
        return None;
    }
    
    // Parse program header offset (offset 32, 8 bytes for 64-bit)
    let ph_offset = u64::from_le_bytes(buf[32..40].try_into().ok()?) as usize;
    let ph_entsize = u16::from_le_bytes(buf[54..56].try_into().ok()?) as usize;
    let ph_num = u16::from_le_bytes(buf[56..58].try_into().ok()?) as usize;
    
    // Look for DYNAMIC segment (PT_DYNAMIC = 2)
    let mut dynamic_offset = None;
    let mut dynamic_size = None;
    
    for i in 0..ph_num {
        let ph_addr = ph_offset + i * ph_entsize;
        if ph_addr + 56 > n {
            break;
        }
        
        let p_type = u32::from_le_bytes(buf[ph_addr..ph_addr+4].try_into().ok()?);
        if p_type == 2 { // PT_DYNAMIC
            let p_offset = u64::from_le_bytes(buf[ph_addr+8..ph_addr+16].try_into().ok()?) as usize;
            let p_filesz = u64::from_le_bytes(buf[ph_addr+32..ph_addr+40].try_into().ok()?) as usize;
            dynamic_offset = Some(p_offset);
            dynamic_size = Some(p_filesz);
            break;
        }
    }
    
    // For now, return None as parsing full ELF and extracting RUNPATH is complex
    // The setenv approach with LD_LIBRARY_PATH should handle most cases
    None
}

fn prepare_exec_target(
    command: &str,
    args: &[String],
    host_root: Option<&Path>,
) -> (String, Vec<String>) {
    let mut exec_path = command.to_string();
    let mut argv = Vec::with_capacity(1 + args.len());
    argv.push(command.to_string());
    argv.extend(args.iter().cloned());

    let Some(root) = host_root else {
        return (exec_path, argv);
    };
    
    let cmd_path = Path::new(command);
    
    // If command is an absolute path without root prefix, redirect it to rootfs
    if cmd_path.is_absolute() && !cmd_path.starts_with(root) {
        let redirected = root.join(command.trim_start_matches('/'));
        if redirected.exists() {
            exec_path = redirected.to_string_lossy().into_owned();
            argv[0] = exec_path.clone();
        }
    }
    
    if !cmd_path.starts_with(root) && !Path::new(&exec_path).starts_with(root) {
        return (exec_path, argv);
    }

    let actual_path = if Path::new(&exec_path).starts_with(root) {
        Path::new(&exec_path)
    } else {
        cmd_path
    };

    let mut file = match std::fs::File::open(actual_path) {
        Ok(f) => f,
        Err(_) => return (exec_path, argv),
    };
    let mut hdr = [0u8; 4096];
    let n = match file.read(&mut hdr) {
        Ok(v) => v,
        Err(_) => return (exec_path, argv),
    };
    let Some(interp) = parse_elf_interp(&hdr[..n]) else {
        return (exec_path, argv);
    };
    if !interp.starts_with('/') {
        return (exec_path, argv);
    }
    let host_interp = root.join(interp.trim_start_matches('/'));
    if !host_interp.exists() {
        return (exec_path, argv);
    }

    let guest_command = actual_path
        .strip_prefix(root)
        .ok()
        .map(|rel| {
            if rel.as_os_str().is_empty() {
                String::from("/")
            } else {
                format!("/{}", rel.to_string_lossy())
            }
        })
        .unwrap_or_else(|| command.to_string());

    exec_path = host_interp.to_string_lossy().into_owned();
    let mut via_interp = Vec::with_capacity(2 + args.len());
    via_interp.push(exec_path.clone());
    via_interp.push(guest_command);
    via_interp.extend(args.iter().cloned());
    (exec_path, via_interp)
}

fn install_seccomp_listener() -> Result<RawFd, String> {
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
        k: AUDIT_ARCH_CURRENT,
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
    let allow_sendmsg = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_SENDMSG as u32,
    };
    let allow_close = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_CLOSE as u32,
    };
    let allow_exit = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_EXIT as u32,
    };
    let allow_exit_group = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_EXIT_GROUP as u32,
    };
    let allow_execve = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_EXECVE as u32,
    };
    let allow_execveat = libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 1,
        k: HOST_NR_EXECVEAT as u32,
    };
    let ret_allow = libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    };
    let ret_notify = libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_USER_NOTIF,
    };

    let filter = [
        arch_check,
        arch_match,
        arch_kill,
        load_nr,
        allow_sendmsg,
        ret_allow,
        allow_close,
        ret_allow,
        allow_exit,
        ret_allow,
        allow_exit_group,
        ret_allow,
        allow_execve,
        ret_allow,
        allow_execveat,
        ret_allow,
        ret_notify,
    ];

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if ret < 0 {
        return Err(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ret as RawFd)
}

fn socketpair_create() -> Result<[RawFd; 2], String> {
    let mut fds = [0; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!("socketpair failed: {}", std::io::Error::last_os_error()));
    }
    Ok(fds)
}

fn send_fd(sock: RawFd, fd: RawFd) -> Result<(), String> {
    let mut buf = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr().cast(),
        msg_controllen: cmsg_buf.len(),
        msg_flags: 0,
    };
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr);
        if cmsg.is_null() {
            return Err(String::from("CMSG_FIRSTHDR failed"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        let data = libc::CMSG_DATA(cmsg) as *mut RawFd;
        std::ptr::write(data, fd);
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
    }
    let ret = unsafe { libc::syscall(libc::SYS_sendmsg, sock, &msg as *const libc::msghdr, 0) };
    if ret < 0 {
        return Err(format!("sendmsg failed: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<RawFd, String> {
    let mut buf = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr().cast(),
        msg_controllen: cmsg_buf.len(),
        msg_flags: 0,
    };
    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        return Err(format!("recvmsg failed: {}", std::io::Error::last_os_error()));
    }
    if ret == 0 {
        return Err(String::from("peer closed socket before sending listener fd"));
    }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr);
        if cmsg.is_null() {
            return Err(String::from("missing cmsg"));
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(String::from("unexpected cmsg type for listener fd"));
        }
        if (*cmsg).cmsg_len < libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize {
            return Err(String::from("short cmsg payload for listener fd"));
        }
        let data = libc::CMSG_DATA(cmsg) as *const RawFd;
        Ok(std::ptr::read(data))
    }
}

fn wait_status_text(status: libc::c_int) -> String {
    if libc::WIFEXITED(status) {
        format!("exit={}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        format!("signal={}", libc::WTERMSIG(status))
    } else {
        String::from("unknown")
    }
}

fn spawn_seccomp_exec_child(
    command: &str,
    args: &[String],
    host_root: Option<&Path>,
    workdir: Option<&Path>,
) -> Result<(RawFd, libc::pid_t), String> {
    let (exec_target, argv) = prepare_exec_target(command, args, host_root);
    let cmd_c = CString::new(exec_target.clone()).map_err(|e| e.to_string())?;
    let mut argv_c = Vec::with_capacity(argv.len());
    for a in &argv {
        argv_c.push(CString::new(a.as_str()).map_err(|e| e.to_string())?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let fd_sock = socketpair_create()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(fd_sock[0]);
        close_fd(fd_sock[1]);
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        close_fd(fd_sock[0]);
        let result = (|| -> Result<(), (String, i32)> {
            if let Some(root) = host_root {
                let root_c = CString::new(root.as_os_str().as_bytes())
                    .map_err(|e| (e.to_string(), 127))?;
                let rc = unsafe { libc::chdir(root_c.as_ptr()) };
                if rc != 0 {
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(127);
                    return Err((
                        format!(
                            "chdir(root={}) failed: {}",
                            root.display(),
                            std::io::Error::last_os_error()
                        ),
                        errno,
                    ));
                }
                let home = root.join("root");
                if let Ok(home_c) = CString::new(home.as_os_str().as_bytes()) {
                    let _ = unsafe { libc::setenv(c"HOME".as_ptr(), home_c.as_ptr(), 1) };
                }
                let _ = unsafe {
                    libc::setenv(
                        c"PWD".as_ptr(),
                        c"/".as_ptr(),
                        1,
                    )
                };
                
                // Setup LD_LIBRARY_PATH to include all lib directories in rootfs
                setup_ld_library_path(root);
            }
            if let Some(dir) = workdir {
                let dir_c =
                    CString::new(dir.as_os_str().as_bytes()).map_err(|e| (e.to_string(), 127))?;
                let rc = unsafe { libc::chdir(dir_c.as_ptr()) };
                if rc != 0 {
                    let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(127);
                    return Err((
                        format!(
                            "chdir(workdir={}) failed: {}",
                            dir.display(),
                            std::io::Error::last_os_error()
                        ),
                        errno,
                    ));
                }
            }
            let prctl_ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if prctl_ret != 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(127);
                return Err((
                    format!(
                        "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                        std::io::Error::last_os_error()
                    ),
                    errno,
                ));
            }
            let listener_fd = install_seccomp_listener().map_err(|e| (e, 127))?;
            send_fd(fd_sock[1], listener_fd).map_err(|e| (e, 127))?;
            close_fd(fd_sock[1]);
            close_fd(listener_fd);

            let ret = unsafe { libc::execv(cmd_c.as_ptr(), argv_ptrs.as_ptr()) };
            let _ = ret;
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(127);
            Err((
                format!(
                    "execve({exec_target}) failed: {}",
                    std::io::Error::last_os_error()
                ),
                errno,
            ))
        })();
        if let Err((e, code)) = result {
            eprintln!("{e}");
            let exit_code = code.clamp(1, 255);
            unsafe { libc::_exit(exit_code) };
        }
        unsafe { libc::_exit(0) };
    }

    close_fd(fd_sock[1]);
    let listener_fd = match recv_fd(fd_sock[0]) {
        Ok(fd) => fd,
        Err(e) => {
            close_fd(fd_sock[0]);
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == 0 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
            }
            let status_txt = wait_status_text(status);
            return Err(format!(
                "failed receiving seccomp listener fd from child: {e} ({status_txt})"
            ));
        }
    };
    close_fd(fd_sock[0]);
    Ok((listener_fd, pid))
}

fn supervise_seccomp_forward_to_lkl(
    listener_fd: RawFd,
    child_pid: libc::pid_t,
    sysnrs: &SysNrs,
    host_root: Option<&Path>,
    verbose: bool,
    root_identity: bool,
    id_override: Option<(libc::uid_t, libc::gid_t)>,
    normalize: bool,
) -> Result<i32, String> {
    let mut table = ForwardFdTable::new();
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        if waited < 0 {
            return Err(format!("waitpid failed: {}", std::io::Error::last_os_error()));
        }
        if waited == child_pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
        }

        let mut pfd = libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 100) };
        if poll_ret < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(format!(
                "poll(seccomp listener) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if poll_ret == 0 {
            continue;
        }
        if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            if waited == child_pid {
                if libc::WIFEXITED(status) {
                    return Ok(libc::WEXITSTATUS(status));
                }
                if libc::WIFSIGNALED(status) {
                    return Ok(128 + libc::WTERMSIG(status));
                }
            }
            continue;
        }

        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        if let Err(e) = notify_recv(listener_fd, &mut req) {
            if let Some(errno) = std::io::Error::last_os_error().raw_os_error() {
                if errno == libc::EINTR || errno == libc::EAGAIN {
                    continue;
                }
                if errno == libc::ENOENT {
                    continue;
                }
            }
            return Err(e);
        }
        let dispatch =
            dispatch_forward_syscall(
                &req,
                sysnrs,
                &mut table,
                host_root,
                verbose,
                listener_fd,
                root_identity,
                id_override,
                normalize,
            );
        let resp = seccomp_response_for(req.id, dispatch);
        notify_send(listener_fd, &resp)?;
    }
}

pub(crate) fn run_seccomp_forward_to_lkl(
    sysnrs: &SysNrs,
    host_cmd: &str,
    command_args: &[String],
    _forward_syscall: &[String],
    host_root: Option<&Path>,
    host_workdir: Option<&Path>,
    forward_verbose: bool,
    root_identity: bool,
    id_override: Option<(libc::uid_t, libc::gid_t)>,
    normalize: bool,
) -> Result<(), String> {
    let _ = sysnrs;
    if host_root.is_none() && host_cmd.starts_with('/') && !Path::new(host_cmd).exists() {
        return Err(format!(
            "forward command path not found on host: {host_cmd}"
        ));
    }

    let (listener_fd, pid) =
        spawn_seccomp_exec_child(host_cmd, command_args, host_root, host_workdir)?;
    let supervised = supervise_seccomp_forward_to_lkl(
        listener_fd,
        pid,
        sysnrs,
        host_root,
        forward_verbose,
        root_identity,
        id_override,
        normalize,
    );
    close_fd(listener_fd);
    let exit_code = match supervised {
        Ok(code) => code,
        Err(e) => {
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut status = 0;
            let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
            return Err(format!("{e} ({})", wait_status_text(status)));
        }
    };
    if exit_code == 0 {
        return Ok(());
    }
    if exit_code == 127 && host_root.is_none() {
        eprintln!(
            "seccomp child failed to exec (status 127), falling back to direct host execution"
        );
        let mut cmd = std::process::Command::new(host_cmd);
        cmd.args(command_args);
        if let Some(dir) = host_workdir {
            cmd.current_dir(dir);
        }
        if let Some(root) = host_root {
            cmd.env("HOME", root.join("root"));
            cmd.env("PWD", "/");
        }
        let status = cmd
            .status()
            .map_err(|e| format!("fallback host exec failed for '{host_cmd}': {e}"))?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("fallback host command exited unsuccessfully: {status}"));
    }
    Err(format!("seccomp child exited with status {exit_code}"))
}

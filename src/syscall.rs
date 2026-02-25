use std::ffi::{CString, c_char, c_int, c_long, c_void};

use crate::lkl::lkl_syscall6;

pub(crate) struct SysNrs {
    chdir: c_long,
    getuid: c_long,
    geteuid: c_long,
    getresuid: c_long,
    getgid: c_long,
    getegid: c_long,
    getresgid: c_long,
    setuid: c_long,
    setreuid: c_long,
    setresuid: c_long,
    setgid: c_long,
    setregid: c_long,
    setresgid: c_long,
    getgroups: c_long,
    setgroups: c_long,
    setfsgid: c_long,
    chroot: c_long,
    mknodat: c_long,
    mkdir_no: c_long,
    mkdirat_style: bool,
    mount: c_long,
    umount2: c_long,
    openat: c_long,
    openat2: c_long,
    fcntl: c_long,
    dup: c_long,
    dup3: c_long,
    close: c_long,
    read: c_long,
    write: c_long,
    pread64: c_long,
    lseek: c_long,
    fstat: c_long,
    newfstatat: c_long,
    faccessat2: c_long,
    getdents: c_long,
    getdents64: c_long,
    mkdirat: c_long,
    unlinkat: c_long,
    renameat2: c_long,
    fchmodat: c_long,
    fchownat: c_long,
    mmap: c_long,
    munmap: c_long,
}

pub(crate) const SYSNRS_X86_64: SysNrs = SysNrs {
    chdir: 80,
    getuid: 102,
    geteuid: 107,
    getresuid: 118,
    getgid: 104,
    getegid: 108,
    getresgid: 120,
    setuid: 105,
    setreuid: 113,
    setresuid: 117,
    setgid: 106,
    setregid: 114,
    setresgid: 119,
    getgroups: 115,
    setgroups: 116,
    setfsgid: 123,
    chroot: 161,
    mknodat: 259,
    mkdir_no: 83,
    mkdirat_style: false,
    mount: 165,
    umount2: 166,
    openat: 257,
    openat2: 437,
    fcntl: 72,
    dup: 32,
    dup3: 292,
    close: 3,
    read: 0,
    write: 1,
    pread64: 17,
    lseek: 8,
    fstat: 5,
    newfstatat: 262,
    faccessat2: 439,
    getdents: 78,
    getdents64: 217,
    mkdirat: 258,
    unlinkat: 263,
    renameat2: 316,
    fchmodat: 268,
    fchownat: 260,
    mmap: 9,
    munmap: 11,
};

pub(crate) const SYSNRS_GENERIC: SysNrs = SysNrs {
    chdir: 49,
    getuid: 174,
    geteuid: 175,
    getresuid: 148,
    getgid: 176,
    getegid: 177,
    getresgid: 150,
    setuid: 146,
    setreuid: 145,
    setresuid: 147,
    setgid: 144,
    setregid: 143,
    setresgid: 149,
    getgroups: 158,
    setgroups: 159,
    setfsgid: 152,
    chroot: 51,
    mknodat: 33,
    mkdir_no: 34,
    mkdirat_style: true,
    mount: 40,
    umount2: 39,
    openat: 56,
    openat2: 437,
    fcntl: 25,
    dup: 23,
    dup3: 24,
    close: 57,
    read: 63,
    write: 64,
    pread64: 67,
    lseek: 62,
    fstat: 80,
    newfstatat: 79,
    faccessat2: 439,
    getdents: -1,
    getdents64: 61,
    mkdirat: 34,
    unlinkat: 35,
    renameat2: 276,
    fchmodat: 53,
    fchownat: 54,
    mmap: 222,
    munmap: 215,
};

pub(crate) const AT_FDCWD_LINUX: c_long = -100;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct OpenHow {
    pub(crate) flags: u64,
    pub(crate) mode: u64,
    pub(crate) resolve: u64,
}

pub(crate) unsafe fn lkl_sys_mount(
    sys: &SysNrs,
    src: *const c_char,
    target: *const c_char,
    fstype: *const c_char,
    flags: c_long,
    data: *const c_void,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.mount,
            src as usize as c_long,
            target as usize as c_long,
            fstype as usize as c_long,
            flags,
            data as usize as c_long,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_umount2(sys: &SysNrs, target: *const c_char, flags: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.umount2, target as usize as c_long, flags, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_openat2(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    how: *const OpenHow,
    size: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.openat2,
            dirfd,
            path as usize as c_long,
            how as usize as c_long,
            size,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_dup(sys: &SysNrs, fd: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.dup, fd, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_dup3(sys: &SysNrs, oldfd: c_long, newfd: c_long, flags: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.dup3, oldfd, newfd, flags, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_mkdir(sys: &SysNrs, path: *const c_char, mode: c_int) -> c_long {
    if sys.mkdirat_style {
        unsafe {
            lkl_syscall6(
                sys.mkdir_no,
                -100,
                path as usize as c_long,
                mode as c_long,
                0,
                0,
                0,
            )
        }
    } else {
        unsafe {
            lkl_syscall6(
                sys.mkdir_no,
                path as usize as c_long,
                mode as c_long,
                0,
                0,
                0,
                0,
            )
        }
    }
}

pub(crate) unsafe fn lkl_sys_chroot(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chroot, path as usize as c_long, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_chdir(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chdir, path as usize as c_long, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getuid(sys: &SysNrs) -> c_long {
    unsafe { lkl_syscall6(sys.getuid, 0, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_geteuid(sys: &SysNrs) -> c_long {
    unsafe { lkl_syscall6(sys.geteuid, 0, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getresuid(
    sys: &SysNrs,
    ruid: *mut libc::uid_t,
    euid: *mut libc::uid_t,
    suid: *mut libc::uid_t,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.getresuid,
            ruid as usize as c_long,
            euid as usize as c_long,
            suid as usize as c_long,
            0,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_getgid(sys: &SysNrs) -> c_long {
    unsafe { lkl_syscall6(sys.getgid, 0, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getegid(sys: &SysNrs) -> c_long {
    unsafe { lkl_syscall6(sys.getegid, 0, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getresgid(
    sys: &SysNrs,
    rgid: *mut libc::gid_t,
    egid: *mut libc::gid_t,
    sgid: *mut libc::gid_t,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.getresgid,
            rgid as usize as c_long,
            egid as usize as c_long,
            sgid as usize as c_long,
            0,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_setuid(sys: &SysNrs, uid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setuid, uid, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_setreuid(sys: &SysNrs, ruid: c_long, euid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setreuid, ruid, euid, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_setresuid(sys: &SysNrs, ruid: c_long, euid: c_long, suid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setresuid, ruid, euid, suid, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_setgid(sys: &SysNrs, gid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setgid, gid, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_setregid(sys: &SysNrs, rgid: c_long, egid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setregid, rgid, egid, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_setresgid(sys: &SysNrs, rgid: c_long, egid: c_long, sgid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setresgid, rgid, egid, sgid, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getgroups(
    sys: &SysNrs,
    gidsetsize: c_long,
    grouplist: *mut libc::gid_t,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.getgroups,
            gidsetsize,
            grouplist as usize as c_long,
            0,
            0,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_setgroups(
    sys: &SysNrs,
    gidsetsize: c_long,
    grouplist: *const libc::gid_t,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.setgroups,
            gidsetsize,
            grouplist as usize as c_long,
            0,
            0,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_setfsgid(sys: &SysNrs, gid: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.setfsgid, gid, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_mknodat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    mode: c_long,
    dev: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.mknodat, dirfd, path as usize as c_long, mode, dev, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_openat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    flags: c_long,
    mode: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.openat,
            dirfd,
            path as usize as c_long,
            flags,
            mode,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_close(sys: &SysNrs, fd: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.close, fd, 0, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_fcntl(
    sys: &SysNrs,
    fd: c_long,
    cmd: c_long,
    arg: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.fcntl, fd, cmd, arg, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_read(sys: &SysNrs, fd: c_long, buf: *mut c_void, len: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.read, fd, buf as usize as c_long, len, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_write(sys: &SysNrs, fd: c_long, buf: *const c_void, len: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.write, fd, buf as usize as c_long, len, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_pread64(
    sys: &SysNrs,
    fd: c_long,
    buf: *mut c_void,
    len: c_long,
    offset: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.pread64, fd, buf as usize as c_long, len, offset, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_lseek(sys: &SysNrs, fd: c_long, offset: c_long, whence: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.lseek, fd, offset, whence, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_fstat(sys: &SysNrs, fd: c_long, statbuf: *mut c_void) -> c_long {
    unsafe { lkl_syscall6(sys.fstat, fd, statbuf as usize as c_long, 0, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_newfstatat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    statbuf: *mut c_void,
    flags: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.newfstatat,
            dirfd,
            path as usize as c_long,
            statbuf as usize as c_long,
            flags,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_faccessat2(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    mode: c_long,
    flags: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.faccessat2,
            dirfd,
            path as usize as c_long,
            mode,
            flags,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_getdents(sys: &SysNrs, fd: c_long, dirp: *mut c_void, count: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.getdents, fd, dirp as usize as c_long, count, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_getdents64(sys: &SysNrs, fd: c_long, dirp: *mut c_void, count: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.getdents64, fd, dirp as usize as c_long, count, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_mkdirat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    mode: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.mkdirat, dirfd, path as usize as c_long, mode, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_unlinkat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    flags: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.unlinkat, dirfd, path as usize as c_long, flags, 0, 0, 0) }
}

pub(crate) unsafe fn lkl_sys_renameat2(
    sys: &SysNrs,
    olddirfd: c_long,
    oldpath: *const c_char,
    newdirfd: c_long,
    newpath: *const c_char,
    flags: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.renameat2,
            olddirfd,
            oldpath as usize as c_long,
            newdirfd,
            newpath as usize as c_long,
            flags,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_fchmodat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    mode: c_long,
    flags: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.fchmodat,
            dirfd,
            path as usize as c_long,
            mode,
            flags,
            0,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_fchownat(
    sys: &SysNrs,
    dirfd: c_long,
    path: *const c_char,
    owner: c_long,
    group: c_long,
    flags: c_long,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.fchownat,
            dirfd,
            path as usize as c_long,
            owner,
            group,
            flags,
            0,
        )
    }
}

pub(crate) unsafe fn lkl_sys_mmap(
    sys: &SysNrs,
    addr: c_long,
    len: c_long,
    prot: c_long,
    flags: c_long,
    fd: c_long,
    offset: c_long,
) -> c_long {
    unsafe { lkl_syscall6(sys.mmap, addr, len, prot, flags, fd, offset) }
}

pub(crate) unsafe fn lkl_sys_munmap(sys: &SysNrs, addr: c_long, len: c_long) -> c_long {
    unsafe { lkl_syscall6(sys.munmap, addr, len, 0, 0, 0, 0) }
}

pub(crate) fn detect_sysnrs() -> Result<&'static SysNrs, String> {
    let p1 = CString::new("/__abi_probe_x64").map_err(|e| e.to_string())?;
    let p2 = CString::new("/__abi_probe_generic").map_err(|e| e.to_string())?;

    let r1 = unsafe { lkl_sys_mkdir(&SYSNRS_X86_64, p1.as_ptr(), 0o755) };
    if r1 == 0 || r1 == -17 {
        return Ok(&SYSNRS_X86_64);
    }

    let r2 = unsafe { lkl_sys_mkdir(&SYSNRS_GENERIC, p2.as_ptr(), 0o755) };
    if r2 == 0 || r2 == -17 {
        return Ok(&SYSNRS_GENERIC);
    }

    Err(format!(
        "unable to detect syscall ABI from mkdir probes: x86_64={r1}, generic={r2}"
    ))
}

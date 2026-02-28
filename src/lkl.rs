use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::os::fd::RawFd;
use std::path::Path;

use crate::syscall::{AT_FDCWD_LINUX, SysNrs, lkl_sys_close, lkl_sys_mkdir, lkl_sys_mknodat, lkl_sys_mmap, lkl_sys_munmap, lkl_sys_openat, lkl_sys_pread64, lkl_sys_unlinkat};

#[repr(C)]
pub(crate) struct LklDisk {
    pub(crate) dev: *mut c_void,
    pub(crate) fd: c_int,
    pub(crate) ops: *mut c_void,
}

pub(crate) fn close_fd(fd: RawFd) {
    if fd >= 0 {
        let _ = unsafe { libc::close(fd) };
    }
}

unsafe extern "C" {
    pub(crate) static mut lkl_host_ops: u8;
    pub(crate) static mut lkl_dev_blk_ops: c_void;

    pub(crate) fn lkl_init(ops: *mut u8) -> c_int;
    pub(crate) fn lkl_start_kernel(cmd: *const c_char, ...) -> c_int;
    pub(crate) fn lkl_cleanup();

    pub(crate) fn lkl_strerror(err: c_int) -> *const c_char;
    pub(crate) fn lkl_syscall(no: c_long, params: *const c_long) -> c_long;

    // LKL-specific mount helpers (available when CONFIG_PROC_FS, CONFIG_SYSFS, CONFIG_DEVTMPFS are enabled)
    pub(crate) fn lkl_mount_proc(fs: *const c_char, mnt: *const c_char) -> c_int;
    pub(crate) fn lkl_mount_sysfs(fs: *const c_char, mnt: *const c_char) -> c_int;
    pub(crate) fn lkl_mount_devtmpfs(fs: *const c_char, mnt: *const c_char) -> c_int;

    pub(crate) fn lkl_disk_add(disk: *mut LklDisk) -> c_int;
    pub(crate) fn lkl_mount_dev(
        disk_id: u32,
        part: u32,
        fs_type: *const c_char,
        flags: c_int,
        opts: *const c_char,
        mnt_str: *mut c_char,
        mnt_str_len: u32,
    ) -> c_long;

    pub(crate) fn virtio_dev_setup(
        dev: *mut crate::host::VirtioDev,
        queues: c_int,
        num_max: c_int,
    ) -> c_int;
    pub(crate) fn virtio_dev_cleanup(dev: *mut crate::host::VirtioDev) -> c_int;
    pub(crate) fn virtio_req_complete(req: *mut crate::host::VirtioReq, len: u32);
}

pub(crate) unsafe fn lkl_syscall6(
    no: c_long,
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
    a6: c_long,
) -> c_long {
    let args = [a1, a2, a3, a4, a5, a6];
    unsafe { lkl_syscall(no, args.as_ptr()) }
}

pub(crate) fn err_text(code: c_long) -> String {
    let e = code as c_int;
    let msg = unsafe { lkl_strerror(e) };
    if msg.is_null() {
        return format!("error {code}");
    }
    unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() }
}

pub(crate) fn ensure_ok(ret: c_long, op: &str) -> Result<(), String> {
    if ret < 0 {
        return Err(format!("{op} failed: {} ({ret})", err_text(ret)));
    }
    Ok(())
}

pub(crate) fn boot_kernel(cmdline: &str) -> Result<(), String> {
    let mut effective_cmdline = cmdline.trim().to_string();
    if !effective_cmdline.contains("console=") {
        if !effective_cmdline.is_empty() {
            effective_cmdline.push(' ');
        }
        effective_cmdline.push_str("console=null");
    }
    let cmdline = CString::new(effective_cmdline).map_err(|e| e.to_string())?;
    unsafe {
        let init_ret = lkl_init(std::ptr::addr_of_mut!(lkl_host_ops));
        if init_ret < 0 {
            return Err(format!(
                "lkl_init failed: {} ({init_ret})",
                err_text(init_ret as c_long)
            ));
        }

        let start_ret = lkl_start_kernel(cmdline.as_ptr());
        if start_ret < 0 {
            lkl_cleanup();
            return Err(format!(
                "lkl_start_kernel failed: {} ({start_ret})",
                err_text(start_ret as c_long)
            ));
        }
    }

    Ok(())
}

pub(crate) fn parse_elf_interp(buf: &[u8]) -> Option<String> {
    if buf.len() < 64 || &buf[..4] != b"\x7FELF" {
        return None;
    }
    if buf[4] != 2 || buf[5] != 1 {
        return None;
    }
    let phoff = u64::from_le_bytes([
        buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
    ]) as usize;
    let phentsize = u16::from_le_bytes([buf[54], buf[55]]) as usize;
    let phnum = u16::from_le_bytes([buf[56], buf[57]]) as usize;
    if phentsize < 56 {
        return None;
    }
    for i in 0..phnum {
        let off = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if off.checked_add(56)? > buf.len() {
            break;
        }
        let p_type = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if p_type != 3 {
            continue;
        }
        let interp_off = u64::from_le_bytes([
            buf[off + 8],
            buf[off + 9],
            buf[off + 10],
            buf[off + 11],
            buf[off + 12],
            buf[off + 13],
            buf[off + 14],
            buf[off + 15],
        ]) as usize;
        let interp_sz = u64::from_le_bytes([
            buf[off + 32],
            buf[off + 33],
            buf[off + 34],
            buf[off + 35],
            buf[off + 36],
            buf[off + 37],
            buf[off + 38],
            buf[off + 39],
        ]) as usize;
        if interp_off >= buf.len() {
            return None;
        }
        let end = interp_off.saturating_add(interp_sz).min(buf.len());
        let mut s = &buf[interp_off..end];
        if let Some(nul) = s.iter().position(|b| *b == 0) {
            s = &s[..nul];
        }
        return Some(String::from_utf8_lossy(s).to_string());
    }
    None
}

pub(crate) fn ensure_dev_console(sysnrs: &SysNrs) {
    let dev_dir = match CString::new("/dev") {
        Ok(v) => v,
        Err(_) => return,
    };
    let console = match CString::new("/dev/console") {
        Ok(v) => v,
        Err(_) => return,
    };

    let mk_dev = unsafe { lkl_sys_mkdir(sysnrs, dev_dir.as_ptr(), 0o755) };
    if mk_dev < 0 && mk_dev != -libc::EEXIST as c_long {
        eprintln!(
            "exec preflight: mkdir /dev failed: {} ({mk_dev})",
            err_text(mk_dev)
        );
    }

    let probe = unsafe {
        lkl_sys_openat(
            sysnrs,
            AT_FDCWD_LINUX,
            console.as_ptr(),
            (libc::O_RDWR | libc::O_CLOEXEC) as c_long,
            0,
        )
    };
    if probe >= 0 {
        let _ = unsafe { lkl_sys_close(sysnrs, probe) };
        eprintln!("exec preflight: /dev/console already present");
        return;
    }
    eprintln!(
        "exec preflight: /dev/console open failed before mknod: {} ({probe})",
        err_text(probe)
    );

    let dev = libc::makedev(5, 1) as c_long;
    let mk_ret = unsafe {
        lkl_sys_mknodat(
            sysnrs,
            AT_FDCWD_LINUX,
            console.as_ptr(),
            (libc::S_IFCHR | 0o600) as c_long,
            dev,
        )
    };
    if mk_ret < 0 && mk_ret != -libc::EEXIST as c_long {
        eprintln!(
            "exec preflight: mknod /dev/console failed: {} ({mk_ret})",
            err_text(mk_ret)
        );
        return;
    }

    let probe2 = unsafe {
        lkl_sys_openat(
            sysnrs,
            AT_FDCWD_LINUX,
            console.as_ptr(),
            (libc::O_RDWR | libc::O_CLOEXEC) as c_long,
            0,
        )
    };
    if probe2 >= 0 {
        let _ = unsafe { lkl_sys_close(sysnrs, probe2) };
        eprintln!("exec preflight: /dev/console open succeeded after mknod");
        return;
    }

    eprintln!(
        "exec preflight: /dev/console open still failed: {} ({probe2}); trying regular-file emulation",
        err_text(probe2)
    );

    let _ = unsafe { lkl_sys_unlinkat(sysnrs, AT_FDCWD_LINUX, console.as_ptr(), 0) };
    let emu_fd = unsafe {
        lkl_sys_openat(
            sysnrs,
            AT_FDCWD_LINUX,
            console.as_ptr(),
            (libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC) as c_long,
            0o600,
        )
    };
    if emu_fd >= 0 {
        eprintln!("exec preflight: emulated /dev/console as regular file (fd={emu_fd})");
        let _ = unsafe { lkl_sys_close(sysnrs, emu_fd) };
    } else {
        eprintln!(
            "exec preflight: regular-file /dev/console emulation failed: {} ({emu_fd})",
            err_text(emu_fd)
        );
    }
}

pub(crate) fn exec_preflight_mmap(sysnrs: &SysNrs, command: &str) {
    const AT_FDCWD: c_long = -100;
    const O_RDONLY: c_long = 0;
    const PROT_READ: c_long = 0x1;
    const PROT_EXEC: c_long = 0x4;
    const MAP_PRIVATE: c_long = 0x02;

    let Ok(path) = CString::new(command) else {
        eprintln!("exec preflight: command contains interior NUL");
        return;
    };

    let fd = unsafe { lkl_sys_openat(sysnrs, AT_FDCWD, path.as_ptr(), O_RDONLY, 0) };
    if fd < 0 {
        eprintln!("exec preflight: openat failed: {} ({fd})", err_text(fd));
        return;
    }
    eprintln!("exec preflight: openat fd={fd}");

    let map = unsafe { lkl_sys_mmap(sysnrs, 0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) };
    if map < 0 {
        eprintln!("exec preflight: mmap failed: {} ({map})", err_text(map));
    } else {
        eprintln!("exec preflight: mmap ok addr=0x{map:x}");
        let unmap = unsafe { lkl_sys_munmap(sysnrs, map, 4096) };
        if unmap < 0 {
            eprintln!(
                "exec preflight: munmap failed: {} ({unmap})",
                err_text(unmap)
            );
        }
    }

    let mut hdr = [0u8; 4096];
    let n = unsafe {
        lkl_sys_pread64(
            sysnrs,
            fd,
            hdr.as_mut_ptr().cast::<c_void>(),
            hdr.len() as c_long,
            0,
        )
    };
    if n > 0 {
        if let Some(interp) = parse_elf_interp(&hdr[..n as usize]) {
            eprintln!(
                "exec preflight: argv0='{}' argv0_basename='{}'",
                command,
                std::path::Path::new(command)
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or(command)
            );
            eprintln!("exec preflight: PT_INTERP='{}'", interp);
            if let Ok(interp_c) = CString::new(interp.clone()) {
                let interp_fd = unsafe {
                    lkl_sys_openat(sysnrs, AT_FDCWD_LINUX, interp_c.as_ptr(), O_RDONLY, 0)
                };
                if interp_fd >= 0 {
                    eprintln!("exec preflight: interpreter open ok fd={interp_fd}");
                    let _ = unsafe { lkl_sys_close(sysnrs, interp_fd) };
                } else {
                    eprintln!(
                        "exec preflight: interpreter open failed: {} ({interp_fd})",
                        err_text(interp_fd)
                    );
                }
            }
        }
    }

    let close = unsafe { lkl_sys_close(sysnrs, fd) };
    if close < 0 {
        eprintln!(
            "exec preflight: close failed: {} ({close})",
            err_text(close)
        );
    }
    ensure_dev_console(sysnrs);
}

pub(crate) fn resolve_guest_command_on_host(command: &str, host_root: Option<&Path>) -> Option<String> {
    let cmd_path = Path::new(command);

    if let Some(root) = host_root {
        let host_path = if cmd_path.is_absolute() {
            root.join(command.trim_start_matches('/'))
        } else {
            root.join(command)
        };
        if host_path.exists() {
            return Some(host_path.to_string_lossy().into_owned());
        }
    }

    if cmd_path.is_absolute() && cmd_path.exists() {
        return Some(command.to_string());
    }

    None
}

pub(crate) fn split_commandline(line: &str) -> Result<(String, Vec<String>), String> {
    let parts = shell_words::split(line).map_err(|e| format!("invalid command line: {e}"))?;
    if parts.is_empty() {
        return Err(String::from("command line cannot be empty"));
    }
    Ok((parts[0].clone(), parts[1..].to_vec()))
}

pub(crate) fn join_mount_opts(opts: &[String]) -> String {
    opts.join(",")
}

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_ulong, c_void};
use std::process::ExitCode;

use clap::Parser;

struct SysNrs {
    chdir: c_long,
    mkdir: c_long,
    chroot: c_long,
    mount: c_long,
    execve: c_long,
}

const SYSNRS_X86_64: SysNrs = SysNrs {
    chdir: 80,
    mkdir: 83,
    chroot: 161,
    mount: 165,
    execve: 59,
};

#[cfg(target_arch = "aarch64")]
// asm-generic numbering (used by aarch64 and some LKL builds)
const SYSNRS_GENERIC: SysNrs = SysNrs {
    chdir: 49,
    mkdir: 34,
    chroot: 51,
    mount: 40,
    execve: 221,
};

#[cfg(target_arch = "x86_64")]
const ACTIVE_SYSNRS: &SysNrs = &SYSNRS_X86_64;
#[cfg(target_arch = "aarch64")]
const ACTIVE_SYSNRS: &SysNrs = &SYSNRS_GENERIC;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported target architecture");

const LKL_MOUNTPOINT: &str = "/__host_rootfs";
const LKL_HOSTFS_TYPE: &str = "hostfs";

#[derive(Parser, Debug)]
#[command(author, version, about = "Boot LKL and run a command from a configured rootfs source")]
struct Cli {
    /// Host folder containing a Linux rootfs tree (e.g. ./debian-rootfs)
    #[arg(
        long = "rootfs-dir",
        required_unless_present_any = ["no_hostfs", "rootfs_9p_addr"]
    )]
    rootfs_dir: Option<String>,

    /// Skip hostfs mount/chroot and run directly in LKL's current root
    #[arg(long = "no-hostfs")]
    no_hostfs: bool,

    /// 9p server endpoint for rootfs mount (format: host:port), e.g. 127.0.0.1:564
    #[arg(long = "rootfs-9p-addr")]
    rootfs_9p_addr: Option<String>,

    /// 9p aname for the remote export
    #[arg(long = "rootfs-9p-aname", default_value = "/")]
    rootfs_9p_aname: String,

    /// 9p msize mount option
    #[arg(long = "rootfs-9p-msize", default_value_t = 262_144)]
    rootfs_9p_msize: u32,

    /// Command to execute inside LKL after chroot (path is inside the rootfs)
    #[arg(long = "command", default_value = "/usr/bin/bash")]
    command: String,

    /// Kernel command line passed to lkl_start_kernel
    #[arg(long = "cmdline", default_value = "mem=1024M loglevel=4")]
    cmdline: String,
}

unsafe extern "C" {
    static mut lkl_host_ops: u8;

    fn lkl_init(ops: *mut u8) -> c_int;
    fn lkl_start_kernel(cmd: *const c_char, ...) -> c_int;
    fn lkl_cleanup();
    fn lkl_syscall(no: c_long, params: *const c_long) -> c_long;
    fn lkl_strerror(err: c_int) -> *const c_char;
}

unsafe fn lkl_syscall6(
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

unsafe fn lkl_sys_mount(
    sys: &SysNrs,
    src: *const c_char,
    target: *const c_char,
    fstype: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.mount,
            src as usize as c_long,
            target as usize as c_long,
            fstype as usize as c_long,
            flags as c_long,
            data as usize as c_long,
            0,
        )
    }
}

unsafe fn lkl_sys_mkdir(sys: &SysNrs, path: *const c_char, mode: c_int) -> c_long {
    unsafe { lkl_syscall6(sys.mkdir, path as usize as c_long, mode as c_long, 0, 0, 0, 0) }
}

unsafe fn lkl_sys_chroot(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chroot, path as usize as c_long, 0, 0, 0, 0, 0) }
}

unsafe fn lkl_sys_execve(
    sys: &SysNrs,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_long {
    unsafe {
        lkl_syscall6(
            sys.execve,
            path as usize as c_long,
            argv as usize as c_long,
            envp as usize as c_long,
            0,
            0,
            0,
        )
    }
}

unsafe fn lkl_sys_chdir(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chdir, path as usize as c_long, 0, 0, 0, 0, 0) }
}

fn err_text(code: c_long) -> String {
    let e = code as c_int;
    let msg = unsafe { lkl_strerror(e) };
    if msg.is_null() {
        return format!("error {}", code);
    }
    unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() }
}

fn ensure_ok(ret: c_long, op: &str) -> Result<(), String> {
    if ret < 0 {
        return Err(format!("{op} failed: {} ({ret})", err_text(ret)));
    }
    Ok(())
}

fn parse_host_port(addr: &str) -> Result<(&str, u16), String> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| "--rootfs-9p-addr must be in host:port format".to_string())?;
    if host.is_empty() {
        return Err("--rootfs-9p-addr host cannot be empty".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| "--rootfs-9p-addr has invalid port".to_string())?;
    Ok((host, port))
}

fn run(cli: Cli) -> Result<(), String> {
    let cmdline = CString::new(cli.cmdline).map_err(|e| e.to_string())?;
    let mountpoint = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let hostfs = CString::new(LKL_HOSTFS_TYPE).map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;
    let init_cmd = CString::new(cli.command).map_err(|e| e.to_string())?;

    let argv = [init_cmd.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    unsafe {
        let init_ret = lkl_init(std::ptr::addr_of_mut!(lkl_host_ops));
        if init_ret < 0 {
            return Err(format!(
                "lkl_init failed: {} ({})",
                err_text(init_ret as c_long),
                init_ret
            ));
        }

        let start_ret = lkl_start_kernel(cmdline.as_ptr());
        if start_ret < 0 {
            lkl_cleanup();
            return Err(format!(
                "lkl_start_kernel failed: {} ({})",
                err_text(start_ret as c_long),
                start_ret
            ));
        }
        let sysnrs = ACTIVE_SYSNRS;

        if let Some(addr) = cli.rootfs_9p_addr.as_deref() {
            let (host, port) = parse_host_port(addr)?;
            let host = CString::new(host).map_err(|e| e.to_string())?;
            let fs_9p = CString::new("9p").map_err(|e| e.to_string())?;
            let data = CString::new(format!(
                "trans=tcp,port={port},msize={},version=9p2000.L,aname={}",
                cli.rootfs_9p_msize, cli.rootfs_9p_aname
            ))
            .map_err(|e| e.to_string())?;

            let _ = lkl_sys_mkdir(sysnrs, mountpoint.as_ptr(), 0o755);
            ensure_ok(
                lkl_sys_mount(
                    sysnrs,
                    host.as_ptr(),
                    mountpoint.as_ptr(),
                    fs_9p.as_ptr(),
                    0,
                    data.as_ptr() as *const c_void,
                ),
                "lkl_sys_mount(9p)",
            )?;
            ensure_ok(lkl_sys_chroot(sysnrs, mountpoint.as_ptr()), "lkl_sys_chroot")?;
            ensure_ok(lkl_sys_chdir(sysnrs, chdir_root.as_ptr()), "lkl_sys_chdir")?;
        } else if !cli.no_hostfs {
            let rootfs_dir = cli
                .rootfs_dir
                .as_ref()
                .ok_or_else(|| "--rootfs-dir is required unless --no-hostfs is set".to_string())?;
            let rootfs_dir = CString::new(rootfs_dir.as_str()).map_err(|e| e.to_string())?;

            // Mount host rootfs folder inside LKL then chroot into it.
            let _ = lkl_sys_mkdir(sysnrs, mountpoint.as_ptr(), 0o755);
            ensure_ok(
                lkl_sys_mount(
                    sysnrs,
                    rootfs_dir.as_ptr(),
                    mountpoint.as_ptr(),
                    hostfs.as_ptr(),
                    0,
                    std::ptr::null(),
                ),
                "lkl_sys_mount(hostfs)",
            )?;

            ensure_ok(lkl_sys_chroot(sysnrs, mountpoint.as_ptr()), "lkl_sys_chroot")?;
            ensure_ok(lkl_sys_chdir(sysnrs, chdir_root.as_ptr()), "lkl_sys_chdir")?;
        }
        let exec_ret = lkl_sys_execve(sysnrs, init_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
        if exec_ret < 0 {
            lkl_cleanup();
            return Err(format!(
                "lkl_sys_execve failed: {} ({})",
                err_text(exec_ret),
                exec_ret
            ));
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

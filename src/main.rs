use std::ffi::{CStr, CString, c_char, c_int, c_long, c_ulong, c_void};
use std::process::ExitCode;

use clap::Parser;

const LKL_MOUNTPOINT: &str = "/__host_rootfs";
const LKL_HOSTFS_TYPE: &str = "hostfs";

#[derive(Parser, Debug)]
#[command(author, version, about = "Boot LKL and run a command from a host rootfs folder")]
struct Cli {
    /// Host folder containing a Linux rootfs tree (e.g. ./debian-rootfs)
    #[arg(long = "rootfs-dir")]
    rootfs_dir: String,

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
    fn lkl_sys_mkdir(path: *const c_char, mode: c_int) -> c_long;
    fn lkl_sys_mount(
        src: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_long;
    fn lkl_sys_chroot(path: *const c_char) -> c_long;
    fn lkl_sys_chdir(path: *const c_char) -> c_long;
    fn lkl_sys_execve(
        path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_long;
    fn lkl_strerror(err: c_int) -> *const c_char;
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

fn run(cli: Cli) -> Result<(), String> {
    let cmdline = CString::new(cli.cmdline).map_err(|e| e.to_string())?;
    let rootfs_dir = CString::new(cli.rootfs_dir).map_err(|e| e.to_string())?;
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

        // Mount host rootfs folder inside LKL then chroot into it.
        let _ = lkl_sys_mkdir(mountpoint.as_ptr(), 0o755);
        ensure_ok(
            lkl_sys_mount(
                rootfs_dir.as_ptr(),
                mountpoint.as_ptr(),
                hostfs.as_ptr(),
                0,
                std::ptr::null(),
            ),
            "lkl_sys_mount(hostfs)",
        )?;

        ensure_ok(lkl_sys_chroot(mountpoint.as_ptr()), "lkl_sys_chroot")?;
        ensure_ok(lkl_sys_chdir(chdir_root.as_ptr()), "lkl_sys_chdir")?;

        let exec_ret = lkl_sys_execve(init_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
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

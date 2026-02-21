use std::env;
use std::ffi::{CStr, CString, c_char, c_int, c_long};
use std::process::ExitCode;

const LKL_ROOTFS_DEFAULT: &str = "/";
const LKL_INIT_DEFAULT: &str = "/usr/bin/bash";
unsafe extern "C" {
    static mut lkl_host_ops: u8;

    fn lkl_init(ops: *mut u8) -> c_int;
    fn lkl_start_kernel(cmd: *const c_char, ...) -> c_int;
    fn lkl_cleanup();
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

fn run() -> Result<(), String> {
    // Rootfs is expected to already exist inside LKL (e.g. initramfs or mounted block device).
    // Example:
    //   LKL_ROOTFS=/ LKL_INIT=/usr/bin/bash cargo run
    //   LKL_ROOTFS=/mnt/rootfs LKL_INIT=/bin/sh cargo run
    let lkl_cmdline = env::var("LKL_CMDLINE").unwrap_or_else(|_| "mem=1024M loglevel=4".to_string());
    let rootfs = env::var("LKL_ROOTFS").unwrap_or_else(|_| LKL_ROOTFS_DEFAULT.to_string());
    let init_cmd = env::var("LKL_INIT").unwrap_or_else(|_| LKL_INIT_DEFAULT.to_string());

    let cmdline = CString::new(lkl_cmdline).map_err(|e| e.to_string())?;
    let chroot_dir = CString::new(rootfs).map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;
    let init = CString::new(init_cmd).map_err(|e| e.to_string())?;

    let argv = [init.as_ptr(), std::ptr::null()];
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

        ensure_ok(lkl_sys_chroot(chroot_dir.as_ptr()), "lkl_sys_chroot")?;
        ensure_ok(lkl_sys_chdir(chdir_root.as_ptr()), "lkl_sys_chdir")?;

        let exec_ret = lkl_sys_execve(init.as_ptr(), argv.as_ptr(), envp.as_ptr());
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
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

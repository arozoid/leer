use std::env;
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::path::Path;
use std::process::ExitCode;

use libloading::os::unix::Library;

const ROOTFS_HOST_PATH: &str = "/home/onyx/sys/debiarm/";
const BASH_GUEST_PATH: &str = "/usr/bin/bash";
const LKL_SO_DEFAULT_PATH: &str = "./liblkl.so";
const LKL_MOUNTPOINT: &str = "/hostroot";
const LKL_NR_MKDIRAT: c_long = 34;
const LKL_NR_MOUNT: c_long = 40;
const LKL_NR_CHDIR: c_long = 49;
const LKL_NR_CHROOT: c_long = 51;
const LKL_NR_EXECVE: c_long = 221;
const LKL_AT_FDCWD: c_long = -100;

#[repr(C)]
struct LklHostOperations {
    _private: [u8; 0],
}

type LklInit = unsafe extern "C" fn(*mut LklHostOperations) -> c_int;
type LklStartKernel = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type LklCleanup = unsafe extern "C" fn();
type LklSyscall = unsafe extern "C" fn(c_long, *const c_long) -> c_long;
type LklStrerror = unsafe extern "C" fn(c_int) -> *const c_char;

struct LklApi {
    _lib: Library,
    host_ops: *mut LklHostOperations,
    init: LklInit,
    start_kernel: LklStartKernel,
    cleanup: LklCleanup,
    syscall: LklSyscall,
    strerror: LklStrerror,
}

impl LklApi {
    fn load() -> Result<Self, String> {
        let lkl_path = env::var("LKL_SO_PATH").unwrap_or_else(|_| LKL_SO_DEFAULT_PATH.to_string());
        let lib = unsafe { Library::new(&lkl_path) }
            .map_err(|e| format!("failed to load liblkl.so from '{}': {e}", lkl_path))?;

        let host_ops = unsafe {
            lib.get::<*mut c_void>(b"lkl_host_ops\0")
                .map_err(|e| format!("missing symbol lkl_host_ops: {e}"))?
                .into_raw() as *mut LklHostOperations
        };
        let init = unsafe {
            *lib.get::<LklInit>(b"lkl_init\0")
                .map_err(|e| format!("missing symbol lkl_init: {e}"))?
        };
        let start_kernel = unsafe {
            *lib.get::<LklStartKernel>(b"lkl_start_kernel\0")
                .map_err(|e| format!("missing symbol lkl_start_kernel: {e}"))?
        };
        let cleanup = unsafe {
            *lib.get::<LklCleanup>(b"lkl_cleanup\0")
                .map_err(|e| format!("missing symbol lkl_cleanup: {e}"))?
        };
        let syscall = unsafe {
            *lib.get::<LklSyscall>(b"lkl_syscall\0")
                .map_err(|e| format!("missing symbol lkl_syscall: {e}"))?
        };
        let strerror = unsafe {
            *lib.get::<LklStrerror>(b"lkl_strerror\0")
                .map_err(|e| format!("missing symbol lkl_strerror: {e}"))?
        };

        Ok(Self {
            _lib: lib,
            host_ops,
            init,
            start_kernel,
            cleanup,
            syscall,
            strerror,
        })
    }

    fn err_text(&self, code: c_long) -> String {
        let e = code as c_int;
        let msg = unsafe { (self.strerror)(e) };
        if msg.is_null() {
            return format!("error {}", code);
        }
        unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() }
    }

    fn ensure_ok(&self, ret: c_long, op: &str) -> Result<(), String> {
        if ret < 0 {
            return Err(format!("{op} failed: {} ({ret})", self.err_text(ret)));
        }
        Ok(())
    }

    fn syscall(&self, no: c_long, args: &[c_long]) -> c_long {
        let mut params = [0 as c_long; 6];
        for (i, arg) in args.iter().enumerate().take(6) {
            params[i] = *arg;
        }
        unsafe { (self.syscall)(no, params.as_ptr()) }
    }
}

fn run() -> Result<(), String> {
    let api = LklApi::load()?;

    let cmdline = CString::new("mem=1024M loglevel=4").map_err(|e| e.to_string())?;
    let root_host = CString::new(ROOTFS_HOST_PATH).map_err(|e| e.to_string())?;
    let mountpoint = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let hostfs = CString::new("hostfs").map_err(|e| e.to_string())?;
    let chroot_dir = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;
    let bash = CString::new(BASH_GUEST_PATH).map_err(|e| e.to_string())?;

    let argv = [bash.as_ptr(), std::ptr::null()];
    let envp: [*const c_char; 1] = [std::ptr::null()];

    unsafe {
        let init_ret = (api.init)(api.host_ops);
        if init_ret < 0 {
            return Err(format!(
                "lkl_init failed: {} ({})",
                api.err_text(init_ret as c_long),
                init_ret
            ));
        }

        let start_ret = (api.start_kernel)(cmdline.as_ptr());
        if start_ret < 0 {
            (api.cleanup)();
            return Err(format!(
                "lkl_start_kernel failed: {} ({})",
                api.err_text(start_ret as c_long),
                start_ret
            ));
        }

        // Create an in-kernel mountpoint and mount hostfs at /hostroot.
        let _ = api.syscall(LKL_NR_MKDIRAT, &[LKL_AT_FDCWD, mountpoint.as_ptr() as c_long, 0o755]);
        let hostfs_ret = api.syscall(
            LKL_NR_MOUNT,
            &[
                root_host.as_ptr() as c_long,
                mountpoint.as_ptr() as c_long,
                hostfs.as_ptr() as c_long,
                0,
                std::ptr::null::<c_void>() as c_long,
            ],
        );
        if hostfs_ret < 0 {
            if hostfs_ret == -19 && Path::new(ROOTFS_HOST_PATH).is_dir() {
                return Err(format!(
                    "hostfs is not available in this liblkl.so (mount returned ENODEV).\n\
                     ROOTFS_HOST_PATH points to a host directory: '{}'.\n\
                     Rebuild liblkl with hostfs support, or use an ext4 disk image and mount it via \
                     lkl_disk_add/lkl_mount_dev.",
                    ROOTFS_HOST_PATH
                ));
            }
            api.ensure_ok(hostfs_ret, "lkl_sys_mount(hostfs)")?;
        }

        api.ensure_ok(
            api.syscall(LKL_NR_CHROOT, &[chroot_dir.as_ptr() as c_long]),
            "lkl_sys_chroot",
        )?;
        api.ensure_ok(
            api.syscall(LKL_NR_CHDIR, &[chdir_root.as_ptr() as c_long]),
            "lkl_sys_chdir",
        )?;

        let exec_ret = api.syscall(
            LKL_NR_EXECVE,
            &[
                bash.as_ptr() as c_long,
                argv.as_ptr() as c_long,
                envp.as_ptr() as c_long,
            ],
        );
        if exec_ret < 0 {
            (api.cleanup)();
            return Err(format!(
                "lkl_sys_execve failed: {} ({})",
                api.err_text(exec_ret),
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

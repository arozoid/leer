use std::env;
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_ulong, c_void};
use std::process::ExitCode;

use libloading::Library;

const ROOTFS_HOST_PATH: &str = "/home/onyx/sys/debian/";
const BASH_HOST_PATH: &str = "/home/onyx/sys/debian/usr/bin/bash";
const LKL_SO_DEFAULT_PATH: &str = "linux/tools/lkl/lib/liblkl.so";
const LKL_MOUNTPOINT: &str = "/hostroot";

#[repr(C)]
struct LklHostOperations {
    _private: [u8; 0],
}

type LklInit = unsafe extern "C" fn(*mut LklHostOperations) -> c_int;
type LklStartKernel = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type LklCleanup = unsafe extern "C" fn();
type LklSysMkdir = unsafe extern "C" fn(*const c_char, c_int) -> c_long;
type LklSysMount = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    c_ulong,
    *const c_void,
) -> c_long;
type LklSysChroot = unsafe extern "C" fn(*const c_char) -> c_long;
type LklSysChdir = unsafe extern "C" fn(*const c_char) -> c_long;
type LklSysExecve =
    unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_long;
type LklStrerror = unsafe extern "C" fn(c_int) -> *const c_char;

struct LklApi {
    _lib: Library,
    host_ops: *mut LklHostOperations,
    init: LklInit,
    start_kernel: LklStartKernel,
    cleanup: LklCleanup,
    sys_mkdir: LklSysMkdir,
    sys_mount: LklSysMount,
    sys_chroot: LklSysChroot,
    sys_chdir: LklSysChdir,
    sys_execve: LklSysExecve,
    strerror: LklStrerror,
}

impl LklApi {
    fn load() -> Result<Self, String> {
        let lkl_path = env::var("LKL_SO_PATH").unwrap_or_else(|_| LKL_SO_DEFAULT_PATH.to_string());
        let lib = unsafe { Library::new(&lkl_path) }
            .map_err(|e| format!("failed to load liblkl.so from '{}': {e}", lkl_path))?;

        let host_ops = unsafe {
            let raw = lib
                .get::<u8>(b"lkl_host_ops\0")
                .map_err(|e| format!("missing symbol lkl_host_ops: {e}"))?;
            (&*raw as *const u8).cast::<LklHostOperations>() as *mut LklHostOperations
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
        let sys_mkdir = unsafe {
            *lib.get::<LklSysMkdir>(b"lkl_sys_mkdir\0")
                .map_err(|e| format!("missing symbol lkl_sys_mkdir: {e}"))?
        };
        let sys_mount = unsafe {
            *lib.get::<LklSysMount>(b"lkl_sys_mount\0")
                .map_err(|e| format!("missing symbol lkl_sys_mount: {e}"))?
        };
        let sys_chroot = unsafe {
            *lib.get::<LklSysChroot>(b"lkl_sys_chroot\0")
                .map_err(|e| format!("missing symbol lkl_sys_chroot: {e}"))?
        };
        let sys_chdir = unsafe {
            *lib.get::<LklSysChdir>(b"lkl_sys_chdir\0")
                .map_err(|e| format!("missing symbol lkl_sys_chdir: {e}"))?
        };
        let sys_execve = unsafe {
            *lib.get::<LklSysExecve>(b"lkl_sys_execve\0")
                .map_err(|e| format!("missing symbol lkl_sys_execve: {e}"))?
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
            sys_mkdir,
            sys_mount,
            sys_chroot,
            sys_chdir,
            sys_execve,
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
}

fn run() -> Result<(), String> {
    let api = LklApi::load()?;

    let cmdline = CString::new("mem=1024M loglevel=4").map_err(|e| e.to_string())?;
    let root_host = CString::new(ROOTFS_HOST_PATH).map_err(|e| e.to_string())?;
    let mountpoint = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let hostfs = CString::new("hostfs").map_err(|e| e.to_string())?;
    let chroot_dir = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;
    let bash = CString::new(BASH_HOST_PATH).map_err(|e| e.to_string())?;

    let argv = [bash.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

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
        let _ = (api.sys_mkdir)(mountpoint.as_ptr(), 0o755);
        api.ensure_ok(
            (api.sys_mount)(
                root_host.as_ptr(),
                mountpoint.as_ptr(),
                hostfs.as_ptr(),
                0,
                std::ptr::null(),
            ),
            "lkl_sys_mount(hostfs)",
        )?;

        api.ensure_ok((api.sys_chroot)(chroot_dir.as_ptr()), "lkl_sys_chroot")?;
        api.ensure_ok((api.sys_chdir)(chdir_root.as_ptr()), "lkl_sys_chdir")?;

        let exec_ret = (api.sys_execve)(bash.as_ptr(), argv.as_ptr(), envp.as_ptr());
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

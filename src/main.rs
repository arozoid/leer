use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about = "LKL runtime with virtio-fs and rootfs image boot modes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start kernel and mount a virtio-fs rootfs
    Virtiofs(VirtiofsArgs),
    /// Start kernel from a rootfs image
    Rootfs(RootfsArgs),
}

#[derive(Args, Debug)]
struct VirtiofsArgs {
    /// Virtio-fs tag name
    #[arg(long = "tag")]
    tag: String,

    /// Mount options passed to virtiofs (optional)
    #[arg(long = "mount-opts")]
    mount_opts: Option<String>,

    /// Command to execute inside mounted rootfs
    #[arg(long = "command", default_value = "/usr/bin/bash")]
    command: String,

    /// Kernel cmdline
    #[arg(long = "cmdline", default_value = "mem=1024M loglevel=4")]
    cmdline: String,
}

#[derive(Args, Debug)]
struct RootfsArgs {
    /// Rootfs image path
    #[arg(long = "image")]
    image: PathBuf,

    /// Filesystem type inside image
    #[arg(long = "fs-type", default_value = "ext4")]
    fs_type: String,

    /// Partition number (0 = whole disk)
    #[arg(long = "part", default_value_t = 0)]
    part: u32,

    /// Optional filesystem mount options
    #[arg(long = "mount-opts")]
    mount_opts: Option<String>,

    /// Command to execute inside mounted rootfs
    #[arg(long = "command", default_value = "/usr/bin/bash")]
    command: String,

    /// Kernel cmdline
    #[arg(long = "cmdline", default_value = "mem=1024M loglevel=4")]
    cmdline: String,
}

struct SysNrs {
    chdir: c_long,
    chroot: c_long,
    execve: c_long,
    mkdir_no: c_long,
    mkdirat_style: bool,
    mount: c_long,
}

const SYSNRS_X86_64: SysNrs = SysNrs {
    chdir: 80,
    chroot: 161,
    execve: 59,
    mkdir_no: 83,
    mkdirat_style: false,
    mount: 165,
};

const SYSNRS_GENERIC: SysNrs = SysNrs {
    chdir: 49,
    chroot: 51,
    execve: 221,
    mkdir_no: 34,
    mkdirat_style: true,
    mount: 40,
};

const LKL_MOUNTPOINT: &str = "/__host_rootfs";

#[repr(C)]
struct LklDisk {
    dev: *mut c_void,
    fd: c_int,
    ops: *mut c_void,
}

unsafe extern "C" {
    static mut lkl_host_ops: u8;
    static mut lkl_dev_blk_ops: c_void;

    fn lkl_init(ops: *mut u8) -> c_int;
    fn lkl_start_kernel(cmd: *const c_char, ...) -> c_int;
    fn lkl_cleanup();

    fn lkl_strerror(err: c_int) -> *const c_char;
    fn lkl_syscall(no: c_long, params: *const c_long) -> c_long;

    fn lkl_mount_fs(fstype: *const c_char) -> c_int;

    fn lkl_disk_add(disk: *mut LklDisk) -> c_int;
    fn lkl_mount_dev(
        disk_id: u32,
        part: u32,
        fs_type: *const c_char,
        flags: c_int,
        opts: *const c_char,
        mnt_str: *mut c_char,
        mnt_str_len: u32,
    ) -> c_long;
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

unsafe fn lkl_sys_mkdir(sys: &SysNrs, path: *const c_char, mode: c_int) -> c_long {
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
        unsafe { lkl_syscall6(sys.mkdir_no, path as usize as c_long, mode as c_long, 0, 0, 0, 0) }
    }
}

unsafe fn lkl_sys_chroot(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chroot, path as usize as c_long, 0, 0, 0, 0, 0) }
}

unsafe fn lkl_sys_chdir(sys: &SysNrs, path: *const c_char) -> c_long {
    unsafe { lkl_syscall6(sys.chdir, path as usize as c_long, 0, 0, 0, 0, 0) }
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

fn err_text(code: c_long) -> String {
    let e = code as c_int;
    let msg = unsafe { lkl_strerror(e) };
    if msg.is_null() {
        return format!("error {code}");
    }
    unsafe { CStr::from_ptr(msg).to_string_lossy().into_owned() }
}

fn ensure_ok(ret: c_long, op: &str) -> Result<(), String> {
    if ret < 0 {
        return Err(format!("{op} failed: {} ({ret})", err_text(ret)));
    }
    Ok(())
}

fn detect_sysnrs() -> Result<&'static SysNrs, String> {
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

fn boot_kernel(cmdline: &str) -> Result<(), String> {
    let cmdline = CString::new(cmdline).map_err(|e| e.to_string())?;
    unsafe {
        let init_ret = lkl_init(std::ptr::addr_of_mut!(lkl_host_ops));
        if init_ret < 0 {
            return Err(format!("lkl_init failed: {} ({init_ret})", err_text(init_ret as c_long)));
        }

        let start_ret = lkl_start_kernel(cmdline.as_ptr());
        if start_ret < 0 {
            lkl_cleanup();
            return Err(format!(
                "lkl_start_kernel failed: {} ({start_ret})",
                err_text(start_ret as c_long)
            ));
        }

        let procfs = CString::new("proc").map_err(|e| e.to_string())?;
        let _ = lkl_mount_fs(procfs.as_ptr());
        let sysfs = CString::new("sysfs").map_err(|e| e.to_string())?;
        let _ = lkl_mount_fs(sysfs.as_ptr());
    }

    Ok(())
}

fn exec_inside_root(sysnrs: &SysNrs, command: &str) -> Result<(), String> {
    let init_cmd = CString::new(command).map_err(|e| e.to_string())?;
    let argv = [init_cmd.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    unsafe {
        let exec_ret = lkl_sys_execve(sysnrs, init_cmd.as_ptr(), argv.as_ptr(), envp.as_ptr());
        if exec_ret < 0 {
            lkl_cleanup();
            return Err(format!(
                "lkl_sys_execve failed: {} ({exec_ret})",
                err_text(exec_ret)
            ));
        }
    }

    Ok(())
}

fn run_virtiofs(args: VirtiofsArgs) -> Result<(), String> {
    boot_kernel(&args.cmdline)?;

    let sysnrs = detect_sysnrs()?;

    let mountpoint = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let fs_virtio = CString::new("virtiofs").map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;
    let src = CString::new(args.tag.as_str()).map_err(|e| e.to_string())?;
    let opts = args.mount_opts.unwrap_or_default();
    let opts_c = CString::new(opts.clone()).map_err(|e| e.to_string())?;

    let mk_ret = unsafe { lkl_sys_mkdir(sysnrs, mountpoint.as_ptr(), 0o755) };
    if mk_ret < 0 && mk_ret != -17 {
        return Err(format!(
            "lkl_sys_mkdir(mountpoint) failed: {} ({mk_ret})",
            err_text(mk_ret)
        ));
    }

    let ret = unsafe {
        lkl_sys_mount(
            sysnrs,
            src.as_ptr(),
            mountpoint.as_ptr(),
            fs_virtio.as_ptr(),
            0,
            if opts.is_empty() {
                std::ptr::null()
            } else {
                opts_c.as_ptr() as *const c_void
            },
        )
    };
    if ret < 0 {
        return Err(format!(
            "lkl_sys_mount(virtiofs) failed: {} ({ret}); tag='{}' opts='{}'. Ensure liblkl is built with virtio-fs support and a matching virtio-fs device/tag is provided.",
            err_text(ret),
            args.tag,
            opts
        ));
    }

    unsafe {
        ensure_ok(lkl_sys_chroot(sysnrs, mountpoint.as_ptr()), "lkl_sys_chroot")?;
        ensure_ok(lkl_sys_chdir(sysnrs, chdir_root.as_ptr()), "lkl_sys_chdir")?;
    }

    exec_inside_root(sysnrs, &args.command)
}

fn run_rootfs(args: RootfsArgs) -> Result<(), String> {
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.image)
        .map_err(|e| format!("failed to open image {}: {e}", args.image.display()))?;

    let mut disk = LklDisk {
        dev: std::ptr::null_mut(),
        fd: image.as_raw_fd(),
        ops: std::ptr::addr_of_mut!(lkl_dev_blk_ops),
    };

    let disk_id = unsafe { lkl_disk_add(&mut disk) };
    if disk_id < 0 {
        return Err(format!(
            "lkl_disk_add failed: {} ({disk_id})",
            err_text(disk_id as c_long)
        ));
    }

    boot_kernel(&args.cmdline)?;

    let fs_type = CString::new(args.fs_type).map_err(|e| e.to_string())?;
    let opts_c = if let Some(opts) = args.mount_opts.as_deref() {
        Some(CString::new(opts).map_err(|e| e.to_string())?)
    } else {
        None
    };

    let mut mount_buf = vec![0u8; 256];
    let mount_ret = unsafe {
        lkl_mount_dev(
            disk_id as u32,
            args.part,
            fs_type.as_ptr(),
            0,
            opts_c
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            mount_buf.as_mut_ptr() as *mut c_char,
            mount_buf.len() as u32,
        )
    };
    if mount_ret < 0 {
        return Err(format!(
            "lkl_mount_dev failed: {} ({mount_ret})",
            err_text(mount_ret)
        ));
    }

    let mnt_ptr = mount_buf.as_ptr() as *const c_char;
    let mountpoint = unsafe { CStr::from_ptr(mnt_ptr) }
        .to_string_lossy()
        .into_owned();

    let sysnrs = detect_sysnrs()?;
    let chroot = CString::new(mountpoint).map_err(|e| e.to_string())?;
    let chdir_root = CString::new("/").map_err(|e| e.to_string())?;

    unsafe {
        ensure_ok(lkl_sys_chroot(sysnrs, chroot.as_ptr()), "lkl_sys_chroot")?;
        ensure_ok(lkl_sys_chdir(sysnrs, chdir_root.as_ptr()), "lkl_sys_chdir")?;
    }

    exec_inside_root(sysnrs, &args.command)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Virtiofs(args) => run_virtiofs(args),
        Commands::Rootfs(args) => run_rootfs(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

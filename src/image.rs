use crate::cli::ImageArgs;
use crate::host::{
    apply_bind_mounts, apply_guest_identity, apply_recommended_mounts, parse_bind_specs,
    select_root_profile,
};
use crate::lkl::{
    LklDisk, boot_kernel, ensure_ok, err_text, exec_preflight_mmap, join_mount_opts,
    lkl_dev_blk_ops, lkl_disk_add, lkl_mount_dev, resolve_guest_command_on_host,
    split_commandline,
};
use crate::seccomp;
use crate::syscall::{detect_sysnrs, lkl_sys_chdir, lkl_sys_chroot};
use std::ffi::{CStr, CString, c_char, c_long};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

pub(crate) fn run_image(args: ImageArgs) -> Result<(), String> {
    let profile = select_root_profile(
        args.root_dir.as_ref(),
        args.recommended_root.as_ref(),
        args.system_root.as_ref(),
        None,
    )?;
    let bind_specs = parse_bind_specs(&args.bind)?;

    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&profile.root_path)
        .map_err(|e| format!("failed to open image {}: {e}", profile.root_path.display()))?;

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
    let opts = join_mount_opts(&args.mount_opt);
    let opts_c = if opts.is_empty() {
        None
    } else {
        Some(CString::new(opts).map_err(|e| e.to_string())?)
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
    let chdir_work = CString::new(args.work_dir.clone()).map_err(|e| e.to_string())?;

    unsafe {
        ensure_ok(lkl_sys_chroot(sysnrs, chroot.as_ptr()), "lkl_sys_chroot")?;
    }
    if profile.recommended {
        apply_recommended_mounts(sysnrs)?;
    }
    apply_bind_mounts(sysnrs, &bind_specs)?;
    apply_guest_identity(
        sysnrs,
        args.root_id || profile.force_root_id,
        args.change_id,
    )?;
    unsafe {
        ensure_ok(lkl_sys_chdir(sysnrs, chdir_work.as_ptr()), "lkl_sys_chdir")?;
    }

    let (command, command_args) = split_commandline(&args.command)?;

    if std::env::var_os("LEER_EXEC_PREFLIGHT").is_some() {
        exec_preflight_mmap(sysnrs, &command);
    }

    let host_cmd = resolve_guest_command_on_host(&command, None).unwrap_or(command);
    seccomp::run_seccomp_forward_to_lkl(
        sysnrs,
        &host_cmd,
        &command_args,
        &args.forward_syscall,
        None,
        None,
        args.forward_verbose,
    )
}

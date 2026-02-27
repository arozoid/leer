use std::ffi::{CString, c_int, c_long, c_void};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};

use vhost_user_backend::bitmap::BitmapMmapRegion;
use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use virtiofsd::descriptor_utils::{Reader as VfReader, Writer as VfWriter};
use virtiofsd::passthrough::{Config as VirtiofsConfig, PassthroughFs};
use virtiofsd::server::Server as VirtioFsServer;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::cli::HostArgs;
use crate::lkl::{
    boot_kernel, ensure_ok, err_text, exec_preflight_mmap, join_mount_opts,
    resolve_guest_command_on_host, split_commandline, virtio_dev_cleanup, virtio_dev_setup,
    virtio_req_complete,
};
use crate::seccomp;
use crate::syscall::{
    SysNrs, detect_sysnrs, lkl_sys_chdir, lkl_sys_chroot, lkl_sys_mkdir, lkl_sys_mount,
    lkl_sys_setfsgid, lkl_sys_setresgid, lkl_sys_setresuid,
};

const LKL_MOUNTPOINT: &str = "/__host_rootfs";
const VIRTIO_ID_FS: u32 = 26;
const VIRTIO_VENDOR_ID: u32 = 0x1af4;
const VIRTIO_REQ_MAX_BUFS: usize = 19;
const LINUX_ENOSYS: i32 = 38;
const QUEUE_MAX_SIZE: u16 = 8;

static FRONTEND_SERVER: LazyLock<Mutex<Option<Arc<VirtioFsServer<PassthroughFs>>>>> =
    LazyLock::new(|| Mutex::new(None));

#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}

#[repr(C)]
pub(crate) struct VirtioReq {
    buf_count: u16,
    buf: [Iovec; VIRTIO_REQ_MAX_BUFS],
    total_len: u32,
}

#[repr(C)]
struct VirtioDevOps {
    check_features: Option<extern "C" fn(dev: *mut VirtioDev) -> c_int>,
    enqueue: Option<extern "C" fn(dev: *mut VirtioDev, q: c_int, req: *mut VirtioReq) -> c_int>,
    acquire_queue: Option<extern "C" fn(dev: *mut VirtioDev, queue_idx: c_int)>,
    release_queue: Option<extern "C" fn(dev: *mut VirtioDev, queue_idx: c_int)>,
}

#[repr(C)]
pub(crate) struct VirtioDev {
    device_id: u32,
    vendor_id: u32,
    device_features: u64,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    queue: *mut c_void,
    queue_notify: u32,
    int_status: u32,
    status: u32,
    config_gen: u32,
    ops: *mut VirtioDevOps,
    irq: c_int,
    config_data: *mut c_void,
    config_len: c_int,
    base: *mut c_void,
    virtio_mmio_id: u32,
}

#[repr(C)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseInHeader {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseOutHeader {
    len: u32,
    error: i32,
    unique: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseOpenIn {
    flags: u32,
    unused: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseReadIn {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDescWire {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

unsafe impl ByteValued for VirtqDescWire {}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseOpenOut {
    fh: u64,
    open_flags: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FuseInitOut {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    unused: [u32; 7],
}

#[derive(Clone, Debug)]
pub(crate) struct RootProfile {
    pub(crate) root_path: PathBuf,
    pub(crate) recommended: bool,
    pub(crate) force_root_id: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct BindSpec {
    source: String,
    target: String,
}

pub(crate) fn select_root_profile(
    root_dir: Option<&PathBuf>,
    recommended_root: Option<&PathBuf>,
    system_root: Option<&PathBuf>,
    default_root: Option<&Path>,
) -> Result<RootProfile, String> {
    let mut selected: Option<RootProfile> = None;
    if let Some(p) = root_dir {
        selected = Some(RootProfile {
            root_path: p.clone(),
            recommended: false,
            force_root_id: false,
        });
    }
    if let Some(p) = recommended_root {
        if selected.is_some() {
            return Err(String::from(
                "`-r`, `-R`, and `-S` are mutually exclusive; pass only one",
            ));
        }
        selected = Some(RootProfile {
            root_path: p.clone(),
            recommended: true,
            force_root_id: false,
        });
    }
    if let Some(p) = system_root {
        if selected.is_some() {
            return Err(String::from(
                "`-r`, `-R`, and `-S` are mutually exclusive; pass only one",
            ));
        }
        selected = Some(RootProfile {
            root_path: p.clone(),
            recommended: true,
            force_root_id: true,
        });
    }
    if let Some(v) = selected {
        return Ok(v);
    }
    let Some(def) = default_root else {
        return Err(String::from(
            "missing root path; pass one of `-r`, `-R`, or `-S`",
        ));
    };
    Ok(RootProfile {
        root_path: def.to_path_buf(),
        recommended: false,
        force_root_id: false,
    })
}

pub(crate) fn parse_bind_specs(specs: &[String]) -> Result<Vec<BindSpec>, String> {
    parse_bind_specs_with_root(specs, None)
}

/// Parse bind specs with an optional root directory for resolving relative paths.
/// The root_dir is the virtio-fs export (host root directory).
/// If provided, relative source paths will be resolved relative to root_dir.
/// If not provided, relative source paths will be resolved relative to current working directory.
pub(crate) fn parse_bind_specs_with_root(
    specs: &[String],
    root_dir: Option<&Path>,
) -> Result<Vec<BindSpec>, String> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let (src, dst) = match spec.split_once(':') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (spec.trim(), spec.trim()),
        };
        if src.is_empty() || dst.is_empty() {
            return Err(format!(
                "invalid --bind value '{spec}'; expected SRC:DST or PATH"
            ));
        }
        if !dst.starts_with('/') {
            return Err(format!(
                "invalid --bind value '{spec}'; DST must be an absolute guest path"
            ));
        }
        // Resolve source path: if relative, resolve against root_dir (virtio-fs export)
        // or current working directory if root_dir is not provided.
        let source = if src.starts_with('/') {
            // Absolute path - use as-is, but validate it's within root_dir if provided
            if let Some(root) = root_dir {
                let src_path = Path::new(src);
                let src_abs = if src_path.is_absolute() {
                    src_path.to_path_buf()
                } else {
                    root.join(src_path)
                };
                let src_canonical = fs::canonicalize(&src_abs).map_err(|e| {
                    format!("failed to canonicalize bind source '{}': {}", src, e)
                })?;
                let root_canonical = fs::canonicalize(root).map_err(|e| {
                    format!("failed to canonicalize root directory: {}", e)
                })?;
                // Check if the source is within the root directory
                if !src_canonical.starts_with(&root_canonical) {
                    return Err(format!(
                        "bind source '{}' is outside the root directory '{}'",
                        src,
                        root.display()
                    ));
                }
                // Return path relative to root for virtio-fs
                let relative = src_canonical.strip_prefix(&root_canonical)
                    .map_err(|e| format!("failed to strip prefix: {}", e))?;
                // Convert to string, ensuring it starts with /
                format!("/{}", relative.to_string_lossy().trim_start_matches('/'))
            } else {
                src.to_string()
            }
        } else {
            // Relative path - resolve against root_dir or current working directory
            let src_path = Path::new(src);
            let resolved = if let Some(root) = root_dir {
                // Resolve relative to root_dir (virtio-fs export)
                root.join(src_path)
            } else {
                // Resolve relative to current working directory
                std::env::current_dir()
                    .map_err(|e| format!("failed to get current directory: {e}"))?
                    .join(src_path)
            };
            // Canonicalize to resolve any .. or . components
            let canonical = fs::canonicalize(&resolved).map_err(|e| {
                format!("failed to resolve bind source path '{}': {}", src, e)
            })?;
            
            // If root_dir is provided, compute relative path from root
            if let Some(root) = root_dir {
                let root_canonical = fs::canonicalize(root).map_err(|e| {
                    format!("failed to canonicalize root directory: {}", e)
                })?;
                // Check if within root
                if !canonical.starts_with(&root_canonical) {
                    return Err(format!(
                        "bind source '{}' is outside the root directory '{}'",
                        src,
                        root.display()
                    ));
                }
                // Return path relative to root for virtio-fs
                let relative = canonical.strip_prefix(&root_canonical)
                    .map_err(|e| format!("failed to strip prefix: {}", e))?;
                format!("/{}", relative.to_string_lossy().trim_start_matches('/'))
            } else {
                canonical.to_string_lossy().into_owned()
            }
        };
        out.push(BindSpec {
            source,
            target: dst.to_string(),
        });
    }
    Ok(out)
}

fn is_tolerable_mkdir_err(ret: c_long) -> bool {
    ret == -libc::EEXIST as c_long
        || ret == -libc::EROFS as c_long
        || ret == -libc::EPERM as c_long
        || ret == -libc::EACCES as c_long
        || ret == -libc::ENOSYS as c_long
        || ret == -libc::ENOTSUP as c_long
}

fn lkl_mkdir_p(sysnrs: &SysNrs, path: &str, mode: c_int) -> Result<(), String> {
    lkl_mkdir_p_with_mode(sysnrs, path, mode, false)
}

fn lkl_mkdir_p_best_effort(sysnrs: &SysNrs, path: &str, mode: c_int) -> Result<(), String> {
    lkl_mkdir_p_with_mode(sysnrs, path, mode, true)
}

fn lkl_mkdir_p_with_mode(
    sysnrs: &SysNrs,
    path: &str,
    mode: c_int,
    best_effort: bool,
) -> Result<(), String> {
    if path.is_empty() || path == "/" {
        return Ok(());
    }
    if !path.starts_with('/') {
        return Err(format!("mkdir_p path must be absolute: {path}"));
    }
    let mut cur = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        cur.push('/');
        cur.push_str(seg);
        let p = CString::new(cur.clone()).map_err(|e| e.to_string())?;
        let ret = unsafe { lkl_sys_mkdir(sysnrs, p.as_ptr(), mode) };
        if ret < 0 && !(best_effort && is_tolerable_mkdir_err(ret)) {
            return Err(format!(
                "lkl_sys_mkdir({}) failed: {} ({ret})",
                cur,
                err_text(ret)
            ));
        }
    }
    Ok(())
}

fn mount_single(
    sysnrs: &SysNrs,
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: c_long,
    data: Option<&str>,
    strict: bool,
) -> Result<(), String> {
    let src_c = CString::new(source).map_err(|e| e.to_string())?;
    let dst_c = CString::new(target).map_err(|e| e.to_string())?;
    let fs_c = if let Some(fs) = fstype {
        Some(CString::new(fs).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let data_c = if let Some(v) = data {
        Some(CString::new(v).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let ret = unsafe {
        lkl_sys_mount(
            sysnrs,
            src_c.as_ptr(),
            dst_c.as_ptr(),
            fs_c.as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            data_c
                .as_ref()
                .map(|v| v.as_ptr() as *const c_void)
                .unwrap_or(std::ptr::null()),
        )
    };
    if ret < 0 {
        let ignorable = ret == -libc::EBUSY as c_long
            || ret == -libc::EEXIST as c_long
            || ret == -libc::ENODEV as c_long
            || ret == -libc::EINVAL as c_long
            || ret == -libc::EPERM as c_long
            || ret == -libc::ENOENT as c_long;
        if !strict && ignorable {
            eprintln!("mount {} -> {} ignored: {} ({ret}) - this may be expected", source, target, err_text(ret));
            return Ok(());
        }
        return Err(format!(
            "mount {} -> {} failed: {} ({ret})",
            source,
            target,
            err_text(ret)
        ));
    }
    eprintln!("mount {} -> {} succeeded", source, target);
    Ok(())
}

pub(crate) fn apply_recommended_mounts(sysnrs: &SysNrs) -> Result<(), String> {
    lkl_mkdir_p_best_effort(sysnrs, "/proc", 0o755)?;
    lkl_mkdir_p_best_effort(sysnrs, "/sys", 0o755)?;
    lkl_mkdir_p_best_effort(sysnrs, "/dev/pts", 0o755)?;
    lkl_mkdir_p_best_effort(sysnrs, "/run", 0o755)?;
    lkl_mkdir_p_best_effort(sysnrs, "/tmp", 0o1777)?;

    // `/proc` is fundamental for shell/userland behavior in recommended profiles.
    // If it cannot be mounted, fail explicitly instead of silently continuing.
    mount_single(sysnrs, "proc", "/proc", Some("proc"), 0, None, true)?;
    mount_single(sysnrs, "sysfs", "/sys", Some("sysfs"), 0, None, false)?;
    mount_single(sysnrs, "devtmpfs", "/dev", Some("devtmpfs"), 0, None, false)?;
    mount_single(
        sysnrs,
        "devpts",
        "/dev/pts",
        Some("devpts"),
        0,
        Some("newinstance,ptmxmode=0666,mode=0620"),
        false,
    )?;
    mount_single(
        sysnrs,
        "tmpfs",
        "/run",
        Some("tmpfs"),
        0,
        Some("mode=755"),
        false,
    )?;
    mount_single(
        sysnrs,
        "tmpfs",
        "/tmp",
        Some("tmpfs"),
        0,
        Some("mode=1777"),
        false,
    )?;
    Ok(())
}

pub(crate) fn apply_bind_mounts(sysnrs: &SysNrs, binds: &[BindSpec]) -> Result<(), String> {
    for bind in binds {
        let target_parent = Path::new(&bind.target).parent().and_then(|p| p.to_str());
        if let Some(parent) = target_parent {
            lkl_mkdir_p(sysnrs, parent, 0o755)?;
        }
        mount_single(
            sysnrs,
            &bind.source,
            &bind.target,
            None,
            (libc::MS_BIND | libc::MS_REC) as c_long,
            None,
            true,
        )?;
    }
    Ok(())
}

pub(crate) fn parse_change_id_spec(spec: Option<&str>) -> Result<Option<(c_long, c_long)>, String> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let (uid_s, gid_s) = spec
        .split_once(':')
        .ok_or_else(|| format!("invalid --change-id '{spec}', expected UID:GID"))?;
    let uid: c_long = uid_s
        .parse::<u32>()
        .map_err(|e| format!("invalid --change-id uid '{uid_s}': {e}"))?
        as c_long;
    let gid: c_long = gid_s
        .parse::<u32>()
        .map_err(|e| format!("invalid --change-id gid '{gid_s}': {e}"))?
        as c_long;
    Ok(Some((uid, gid)))
}

pub(crate) fn apply_guest_identity(
    sysnrs: &SysNrs,
    root_id: bool,
    change_id: Option<(c_long, c_long)>,
) -> Result<(), String> {
    if root_id && change_id.is_some() {
        return Err(String::from(
            "`--root-id` and `--change-id` are mutually exclusive",
        ));
    }
    if !root_id && change_id.is_none() {
        return Ok(());
    }

    let (uid, gid, groups): (c_long, c_long, Vec<libc::gid_t>) = if root_id {
        (0, 0, vec![0 as libc::gid_t])
    } else {
        let (uid, gid) = change_id.expect("checked above");
        let groups = vec![gid as libc::gid_t];
        (uid, gid, groups)
    };

    // Avoid LKL setgroups credential mutation. Group identity exposed to child
    // process is handled via seccomp get* overrides.
    let _ = groups;

    let set_gid = unsafe { lkl_sys_setresgid(sysnrs, gid, gid, gid) };
    ensure_ok(set_gid, "lkl_sys_setresgid")?;
    let set_uid = unsafe { lkl_sys_setresuid(sysnrs, uid, uid, uid) };
    ensure_ok(set_uid, "lkl_sys_setresuid")?;
    let set_fsgid = unsafe { lkl_sys_setfsgid(sysnrs, gid) };
    ensure_ok(set_fsgid, "lkl_sys_setfsgid")?;
    Ok(())
}

fn guest_path_from_host_path(path: &Path, root: &Path) -> Result<String, String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    if root == Path::new("/") {
        return Ok(path.to_string_lossy().into_owned());
    }
    let rel = path
        .strip_prefix(root)
        .map_err(|_| format!("path {} is outside root {}", path.display(), root.display()))?;
    if rel.as_os_str().is_empty() {
        return Ok(String::from("/"));
    }
    Ok(format!("/{}", rel.to_string_lossy()))
}

pub(crate) fn resolve_host_workdir(
    root_dir: &Path,
    work_dir: Option<&Path>,
) -> Result<(PathBuf, String), String> {
    let root = if root_dir.is_absolute() {
        root_dir.to_path_buf()
    } else {
        fs::canonicalize(root_dir).map_err(|e| {
            format!(
                "failed to canonicalize root dir {}: {e}",
                root_dir.display()
            )
        })?
    };
    let host_workdir = match work_dir {
        Some(w) if w.is_absolute() => w.to_path_buf(),
        Some(w) => root.join(w),
        None => root.clone(),
    };
    let guest_workdir = guest_path_from_host_path(&host_workdir, &root)?;
    Ok((host_workdir, guest_workdir))
}

fn copy_from_req(req: &VirtioReq, mut offset: usize, out: &mut [u8]) -> bool {
    let mut written = 0usize;
    for i in 0..req.buf_count as usize {
        if i >= VIRTIO_REQ_MAX_BUFS {
            return false;
        }
        let seg = req.buf[i];
        if seg.iov_base.is_null() || seg.iov_len == 0 {
            continue;
        }
        if offset >= seg.iov_len {
            offset -= seg.iov_len;
            continue;
        }
        let seg_ptr = seg.iov_base as *const u8;
        let to_copy = (seg.iov_len - offset).min(out.len() - written);
        if to_copy == 0 {
            break;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                seg_ptr.add(offset),
                out.as_mut_ptr().add(written),
                to_copy,
            );
        }
        written += to_copy;
        offset = 0;
        if written == out.len() {
            return true;
        }
    }
    false
}

fn copy_to_req(req: &VirtioReq, mut offset: usize, inp: &[u8]) -> bool {
    let mut consumed = 0usize;
    for i in 0..req.buf_count as usize {
        if i >= VIRTIO_REQ_MAX_BUFS {
            return false;
        }
        let seg = req.buf[i];
        if seg.iov_base.is_null() || seg.iov_len == 0 {
            continue;
        }
        if offset >= seg.iov_len {
            offset -= seg.iov_len;
            continue;
        }
        let seg_ptr = seg.iov_base as *mut u8;
        let to_copy = (seg.iov_len - offset).min(inp.len() - consumed);
        if to_copy == 0 {
            break;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(inp.as_ptr().add(consumed), seg_ptr.add(offset), to_copy);
        }
        consumed += to_copy;
        offset = 0;
        if consumed == inp.len() {
            return true;
        }
    }
    false
}

fn split_offset_at_iov_boundary(req: &VirtioReq, in_len: usize) -> Option<usize> {
    let mut acc = 0usize;
    for i in 0..req.buf_count as usize {
        if i >= VIRTIO_REQ_MAX_BUFS {
            return None;
        }
        let seg = req.buf[i];
        if seg.iov_len == 0 {
            continue;
        }
        acc = acc.checked_add(seg.iov_len)?;
        if acc >= in_len {
            return Some(acc);
        }
    }
    None
}

extern "C" fn inproc_check_features(_dev: *mut VirtioDev) -> c_int {
    0
}

fn encode_error_reply(req: &VirtioReq, errno: i32) -> u32 {
    let mut in_hdr_buf = [0u8; std::mem::size_of::<FuseInHeader>()];
    if !copy_from_req(req, 0, &mut in_hdr_buf) {
        return 0;
    }
    let in_header = unsafe { std::ptr::read_unaligned(in_hdr_buf.as_ptr() as *const FuseInHeader) };
    let write_off = in_header.len as usize;
    let out_header = FuseOutHeader {
        len: std::mem::size_of::<FuseOutHeader>() as u32,
        error: -errno,
        unique: in_header.unique,
    };
    let out_bytes = unsafe {
        std::slice::from_raw_parts(
            (&out_header as *const FuseOutHeader) as *const u8,
            std::mem::size_of::<FuseOutHeader>(),
        )
    };
    if !copy_to_req(req, write_off, out_bytes) {
        return 0;
    }
    std::mem::size_of::<FuseOutHeader>() as u32
}

fn handle_inproc_request(req: &VirtioReq) -> Result<u32, String> {
    let server = FRONTEND_SERVER
        .lock()
        .map_err(|e| format!("frontend server slot poisoned: {e}"))?
        .clone()
        .ok_or_else(|| String::from("missing inproc frontend server"))?;

    let trace = std::env::var_os("LEER_VIRTIOFS_TRACE").is_some();

    let mut in_hdr_buf = [0u8; std::mem::size_of::<FuseInHeader>()];
    if !copy_from_req(req, 0, &mut in_hdr_buf) {
        return Err(String::from(
            "failed to read FUSE input header from request iovecs",
        ));
    }
    let in_header = unsafe { std::ptr::read_unaligned(in_hdr_buf.as_ptr() as *const FuseInHeader) };
    let in_len = in_header.len as usize;
    let req_total = req.total_len as usize;
    if in_len < std::mem::size_of::<FuseInHeader>() || in_len > req_total {
        return Err(format!(
            "invalid FUSE in-header length: {} (total={req_total})",
            in_len
        ));
    }
    let split_off = split_offset_at_iov_boundary(req, in_len)
        .ok_or_else(|| String::from("unable to determine iov boundary for request split"))?;
    let out_cap = req_total.saturating_sub(split_off);
    if trace {
        let mut lens = Vec::new();
        for i in 0..(req.buf_count as usize).min(6) {
            if i >= VIRTIO_REQ_MAX_BUFS {
                break;
            }
            lens.push(req.buf[i].iov_len);
        }
        eprintln!(
            "virtiofs req: opcode={} unique={} in_len={} split_off={} out_cap={} buf_count={} lens={:?}",
            in_header.opcode, in_header.unique, in_len, split_off, out_cap, req.buf_count, lens
        );
    }

    let mut in_bytes = vec![0u8; in_len];
    if !copy_from_req(req, 0, &mut in_bytes) {
        return Err(String::from(
            "failed to read full FUSE request payload from iovecs",
        ));
    }
    if trace {
        match in_header.opcode {
            1 => {
                let base = std::mem::size_of::<FuseInHeader>();
                if in_bytes.len() > base {
                    let tail = &in_bytes[base..];
                    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
                    let name = String::from_utf8_lossy(&tail[..end]);
                    eprintln!(
                        "virtiofs lookup: parent_ino={} name='{}'",
                        in_header.nodeid, name
                    );
                }
            }
            14 => {
                let base = std::mem::size_of::<FuseInHeader>();
                if in_bytes.len() >= base + std::mem::size_of::<FuseOpenIn>() {
                    let oi = unsafe {
                        std::ptr::read_unaligned(in_bytes[base..].as_ptr() as *const FuseOpenIn)
                    };
                    eprintln!(
                        "virtiofs open: ino={} flags=0x{:x}",
                        in_header.nodeid, oi.flags
                    );
                }
            }
            15 => {
                let base = std::mem::size_of::<FuseInHeader>();
                if in_bytes.len() >= base + std::mem::size_of::<FuseReadIn>() {
                    let ri = unsafe {
                        std::ptr::read_unaligned(in_bytes[base..].as_ptr() as *const FuseReadIn)
                    };
                    eprintln!(
                        "virtiofs read: ino={} fh={} off={} size={}",
                        in_header.nodeid, ri.fh, ri.offset, ri.size
                    );
                }
            }
            _ => {}
        }
    }

    let desc_addr = GuestAddress(0x1000);
    let avail_addr = GuestAddress(0x2000);
    let used_addr = GuestAddress(0x3000);
    let in_addr = GuestAddress(0x4000);
    let out_addr = GuestAddress(0x4000 + (((in_len as u64) + 0xfff) & !0xfff));
    let mem_size = out_addr.raw_value() + (((out_cap as u64) + 0xfff) & !0xfff) + 0x4000;
    let mem_size = usize::try_from(mem_size)
        .map_err(|_| format!("temporary guest memory size too large: {mem_size}"))?;

    let mem = GuestMemoryMmap::<BitmapMmapRegion>::from_ranges(&[(GuestAddress(0), mem_size)])
        .map_err(|e| format!("failed to allocate temporary guest memory: {e}"))?;

    mem.write_slice(&in_bytes, in_addr)
        .map_err(|e| format!("failed to write request payload into temporary guest memory: {e}"))?;

    let d0 = VirtqDescWire {
        addr: in_addr.raw_value().to_le(),
        len: (in_len as u32).to_le(),
        flags: if out_cap > 0 {
            (VRING_DESC_F_NEXT as u16).to_le()
        } else {
            0u16.to_le()
        },
        next: if out_cap > 0 {
            1u16.to_le()
        } else {
            0u16.to_le()
        },
    };
    mem.write_obj(d0, desc_addr)
        .map_err(|e| format!("failed to write descriptor 0: {e}"))?;
    if out_cap > 0 {
        let d1 = VirtqDescWire {
            addr: out_addr.raw_value().to_le(),
            len: (out_cap as u32).to_le(),
            flags: (VRING_DESC_F_WRITE as u16).to_le(),
            next: 0u16.to_le(),
        };
        mem.write_obj(
            d1,
            desc_addr
                .checked_add(std::mem::size_of::<VirtqDescWire>() as u64)
                .ok_or_else(|| String::from("descriptor table address overflow"))?,
        )
        .map_err(|e| format!("failed to write descriptor 1: {e}"))?;
    }

    mem.write_obj(u16::to_le(0), avail_addr)
        .map_err(|e| format!("failed to init avail.flags: {e}"))?;
    mem.write_obj(
        u16::to_le(1),
        avail_addr
            .checked_add(2)
            .ok_or_else(|| String::from("avail idx address overflow"))?,
    )
    .map_err(|e| format!("failed to write avail.idx: {e}"))?;
    mem.write_obj(
        u16::to_le(0),
        avail_addr
            .checked_add(4)
            .ok_or_else(|| String::from("avail ring[0] address overflow"))?,
    )
    .map_err(|e| format!("failed to write avail.ring[0]: {e}"))?;
    mem.write_obj(u16::to_le(0), used_addr)
        .map_err(|e| format!("failed to init used.flags: {e}"))?;
    mem.write_obj(
        u16::to_le(0),
        used_addr
            .checked_add(2)
            .ok_or_else(|| String::from("used idx address overflow"))?,
    )
    .map_err(|e| format!("failed to init used.idx: {e}"))?;

    let mut q = Queue::new(QUEUE_MAX_SIZE).map_err(|e| format!("failed to create queue: {e}"))?;
    q.set_size(QUEUE_MAX_SIZE);
    q.set_desc_table_address(
        Some(desc_addr.raw_value() as u32),
        Some((desc_addr.raw_value() >> 32) as u32),
    );
    q.set_avail_ring_address(
        Some(avail_addr.raw_value() as u32),
        Some((avail_addr.raw_value() >> 32) as u32),
    );
    q.set_used_ring_address(
        Some(used_addr.raw_value() as u32),
        Some((used_addr.raw_value() >> 32) as u32),
    );
    q.set_ready(true);
    if !q.is_valid(&mem) {
        return Err(String::from("temporary queue configuration is invalid"));
    }

    let mut iter = q
        .iter(&mem)
        .map_err(|e| format!("failed to iterate temporary queue: {e}"))?;
    let chain = iter
        .next()
        .ok_or_else(|| String::from("temporary queue did not produce a descriptor chain"))?;
    let reader = VfReader::new(&mem, chain.clone())
        .map_err(|e| format!("failed to create FUSE reader: {e}"))?;
    let writer =
        VfWriter::new(&mem, chain).map_err(|e| format!("failed to create FUSE writer: {e}"))?;

    let out_len = server
        .handle_message(reader, writer, Option::<&mut ()>::None)
        .map_err(|e| format!("inproc virtio-fs request handling failed: {e}"))?;

    if out_len > 0 {
        if out_cap == 0 {
            return Err(format!(
                "server returned {} bytes for a request without writable response buffers",
                out_len
            ));
        }
        let mut out_bytes = vec![0u8; out_len];
        mem.read_slice(&mut out_bytes, out_addr).map_err(|e| {
            format!("failed to read response payload from temporary guest memory: {e}")
        })?;
        if !copy_to_req(req, split_off, &out_bytes) {
            return Err(String::from(
                "failed to write response payload back to virtio request buffers",
            ));
        }
        if trace {
            let mut verify = vec![0u8; out_len];
            if copy_from_req(req, split_off, &mut verify) {
                if verify != out_bytes {
                    let first_diff = verify
                        .iter()
                        .zip(out_bytes.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    eprintln!(
                        "virtiofs verify mismatch at byte {} (req={:02x} out={:02x})",
                        first_diff, verify[first_diff], out_bytes[first_diff]
                    );
                }
            } else {
                eprintln!("virtiofs verify: failed to read response bytes back from req iovecs");
            }
        }

        if trace && out_len >= std::mem::size_of::<FuseOutHeader>() {
            let mut out_hdr = [0u8; std::mem::size_of::<FuseOutHeader>()];
            out_hdr.copy_from_slice(&out_bytes[..std::mem::size_of::<FuseOutHeader>()]);
            let hdr = unsafe { std::ptr::read_unaligned(out_hdr.as_ptr() as *const FuseOutHeader) };
            eprintln!(
                "virtiofs rsp: unique={} len={} error={}",
                hdr.unique, hdr.len, hdr.error
            );
            if in_header.opcode == 26
                && out_bytes.len()
                    >= std::mem::size_of::<FuseOutHeader>() + std::mem::size_of::<FuseInitOut>()
            {
                let base = std::mem::size_of::<FuseOutHeader>();
                let init_out = unsafe {
                    std::ptr::read_unaligned(out_bytes[base..].as_ptr() as *const FuseInitOut)
                };
                eprintln!(
                    "virtiofs init_out: major={} minor={} flags=0x{:x} flags2=0x{:x} max_write={} max_pages={} map_alignment={}",
                    init_out.major,
                    init_out.minor,
                    init_out.flags,
                    init_out.flags2,
                    init_out.max_write,
                    init_out.max_pages,
                    init_out.map_alignment
                );
            }
            if in_header.opcode == 14
                && out_bytes.len()
                    >= std::mem::size_of::<FuseOutHeader>() + std::mem::size_of::<FuseOpenOut>()
            {
                let base = std::mem::size_of::<FuseOutHeader>();
                let open_out = unsafe {
                    std::ptr::read_unaligned(out_bytes[base..].as_ptr() as *const FuseOpenOut)
                };
                eprintln!(
                    "virtiofs open_out: fh={} open_flags=0x{:x}",
                    open_out.fh, open_out.open_flags
                );
            }
            if in_header.opcode == 15 && out_bytes.len() > std::mem::size_of::<FuseOutHeader>() + 4
            {
                let p = &out_bytes[std::mem::size_of::<FuseOutHeader>()..];
                eprintln!(
                    "virtiofs read payload[0..20]: \
{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} \
{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    p[0],
                    p[1],
                    p[2],
                    p[3],
                    p[4],
                    p[5],
                    p[6],
                    p[7],
                    p[8],
                    p[9],
                    p[10],
                    p[11],
                    p[12],
                    p[13],
                    p[14],
                    p[15],
                    p[16],
                    p[17],
                    p[18],
                    p[19]
                );
                if p.len() >= 64 && p[0..4] == [0x7f, b'E', b'L', b'F'] {
                    let e_phoff = u64::from_le_bytes([
                        p[32], p[33], p[34], p[35], p[36], p[37], p[38], p[39],
                    ]) as usize;
                    let e_phentsize = u16::from_le_bytes([p[54], p[55]]) as usize;
                    let e_phnum = u16::from_le_bytes([p[56], p[57]]) as usize;
                    eprintln!(
                        "virtiofs elf: phoff={} phentsize={} phnum={}",
                        e_phoff, e_phentsize, e_phnum
                    );
                    if e_phentsize >= 56 {
                        for i in 0..e_phnum.min(16) {
                            let off = match e_phoff.checked_add(i.saturating_mul(e_phentsize)) {
                                Some(v) => v,
                                None => break,
                            };
                            if off + 56 > p.len() {
                                break;
                            }
                            let p_type =
                                u32::from_le_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]]);
                            if p_type == 3 {
                                let interp_off = u64::from_le_bytes([
                                    p[off + 8],
                                    p[off + 9],
                                    p[off + 10],
                                    p[off + 11],
                                    p[off + 12],
                                    p[off + 13],
                                    p[off + 14],
                                    p[off + 15],
                                ]) as usize;
                                let interp_sz = u64::from_le_bytes([
                                    p[off + 32],
                                    p[off + 33],
                                    p[off + 34],
                                    p[off + 35],
                                    p[off + 36],
                                    p[off + 37],
                                    p[off + 38],
                                    p[off + 39],
                                ]) as usize;
                                if interp_off < p.len() {
                                    let end = interp_off.saturating_add(interp_sz).min(p.len());
                                    let mut s = &p[interp_off..end];
                                    if let Some(pos) = s.iter().position(|b| *b == 0) {
                                        s = &s[..pos];
                                    }
                                    eprintln!(
                                        "virtiofs elf interp: '{}' (off={} size={})",
                                        String::from_utf8_lossy(s),
                                        interp_off,
                                        interp_sz
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    u32::try_from(out_len).map_err(|_| format!("response too large for used.len: {out_len}"))
}

extern "C" fn inproc_enqueue(dev: *mut VirtioDev, _q: c_int, req: *mut VirtioReq) -> c_int {
    let _ = dev;
    if req.is_null() {
        return -1;
    }
    let req_ref = unsafe { &*req };

    let used_len = match handle_inproc_request(req_ref) {
        Ok(len) => len,
        Err(e) => {
            eprintln!("{e}");
            encode_error_reply(req_ref, LINUX_ENOSYS)
        }
    };

    unsafe { virtio_req_complete(req, used_len) };
    0
}

struct InprocVirtioFsFrontend {
    dev: Box<VirtioDev>,
    _ops: Box<VirtioDevOps>,
    _cfg: Box<VirtioFsConfig>,
}

impl InprocVirtioFsFrontend {
    fn new(tag: &str, export_dir: PathBuf) -> Result<Self, String> {
        if !export_dir.exists() {
            return Err(format!(
                "inproc export directory does not exist: {}",
                export_dir.display()
            ));
        }
        if !export_dir.is_dir() {
            return Err(format!(
                "inproc export path is not a directory: {}",
                export_dir.display()
            ));
        }

        let mut cfg = Box::new(VirtioFsConfig {
            tag: [0u8; 36],
            num_request_queues: 1,
        });
        let tag_bytes = tag.as_bytes();
        if tag_bytes.len() >= cfg.tag.len() {
            return Err(format!(
                "virtio-fs tag too long: {} bytes (max {})",
                tag_bytes.len(),
                cfg.tag.len() - 1
            ));
        }
        cfg.tag[..tag_bytes.len()].copy_from_slice(tag_bytes);

        let mut passthrough_cfg = VirtiofsConfig::default();
        passthrough_cfg.root_dir = export_dir.to_string_lossy().into_owned();
        passthrough_cfg.inode_file_handles = Default::default();
        let fs = PassthroughFs::new(passthrough_cfg)
            .map_err(|e| format!("failed to create inproc virtio-fs backend: {e}"))?;
        let server = Arc::new(VirtioFsServer::new(fs));

        let mut ops = Box::new(VirtioDevOps {
            check_features: Some(inproc_check_features),
            enqueue: Some(inproc_enqueue),
            acquire_queue: None,
            release_queue: None,
        });

        let mut dev = Box::new(VirtioDev {
            device_id: VIRTIO_ID_FS,
            vendor_id: VIRTIO_VENDOR_ID,
            device_features: 0,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queue: std::ptr::null_mut(),
            queue_notify: 0,
            int_status: 0,
            status: 0,
            config_gen: 0,
            ops: &mut *ops,
            irq: 0,
            config_data: (&mut *cfg as *mut VirtioFsConfig).cast::<c_void>(),
            config_len: std::mem::size_of::<VirtioFsConfig>() as c_int,
            base: std::ptr::null_mut(),
            virtio_mmio_id: 0,
        });

        *FRONTEND_SERVER
            .lock()
            .map_err(|e| format!("frontend server slot poisoned: {e}"))? = Some(server.clone());

        let ret = unsafe { virtio_dev_setup(&mut *dev, 2, 128) };
        if ret < 0 {
            if let Ok(mut slot) = FRONTEND_SERVER.lock() {
                *slot = None;
            }
            return Err(format!(
                "virtio_dev_setup(virtio-fs frontend) failed: {ret}"
            ));
        }

        Ok(Self {
            dev,
            _ops: ops,
            _cfg: cfg,
        })
    }
}

impl Drop for InprocVirtioFsFrontend {
    fn drop(&mut self) {
        let _ = unsafe { virtio_dev_cleanup(&mut *self.dev) };
        if let Ok(mut slot) = FRONTEND_SERVER.lock() {
            *slot = None;
        }
    }
}

pub(crate) fn run_host(args: HostArgs) -> Result<(), String> {
    let profile = select_root_profile(
        args.root_dir.as_ref(),
        args.recommended_root.as_ref(),
        args.system_root.as_ref(),
        Some(Path::new("/")),
    )?;

    if !profile.root_path.exists() {
        return Err(format!(
            "root directory does not exist: {}",
            profile.root_path.display()
        ));
    }
    if !profile.root_path.is_dir() {
        return Err(format!(
            "root path is not a directory: {}",
            profile.root_path.display()
        ));
    }

    let root_dir = fs::canonicalize(&profile.root_path).map_err(|e| {
        format!(
            "failed to canonicalize root directory {}: {e}",
            profile.root_path.display()
        )
    })?;
    let bind_specs = parse_bind_specs_with_root(&args.bind, Some(&root_dir))?;
    let force_root_id = profile.force_root_id;
    let (host_workdir, guest_workdir) = resolve_host_workdir(&root_dir, args.work_dir.as_deref())?;
    if !host_workdir.exists() || !host_workdir.is_dir() {
        return Err(format!(
            "work directory is not a directory: {}",
            host_workdir.display()
        ));
    }

    boot_kernel(&args.cmdline)?;

    let sysnrs = detect_sysnrs()?;

    let _frontend = Some(InprocVirtioFsFrontend::new("rootfs", root_dir.clone())?);

    let mountpoint = CString::new(LKL_MOUNTPOINT).map_err(|e| e.to_string())?;
    let fs_virtio = CString::new("virtiofs").map_err(|e| e.to_string())?;
    let src = CString::new("rootfs").map_err(|e| e.to_string())?;
    let opts = join_mount_opts(&args.mount_opt);
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
            "lkl_sys_mount(virtiofs) failed: {} ({ret}); tag='{}' opts='{}'",
            err_text(ret),
            "rootfs",
            opts
        ));
    }

    let guest_workdir_c = CString::new(guest_workdir.clone()).map_err(|e| e.to_string())?;
    unsafe {
        ensure_ok(
            lkl_sys_chroot(sysnrs, mountpoint.as_ptr()),
            "lkl_sys_chroot",
        )?;
    }

    if profile.recommended {
        apply_recommended_mounts(sysnrs)?;
    }
    apply_bind_mounts(sysnrs, &bind_specs)?;

    unsafe {
        ensure_ok(
            lkl_sys_chdir(sysnrs, guest_workdir_c.as_ptr()),
            "lkl_sys_chdir",
        )?;
    }
    let change_id = parse_change_id_spec(args.change_id.as_deref())?;
    if args.root_id || force_root_id {
        apply_guest_identity(sysnrs, true, None)?;
    }
    let id_override = change_id.map(|(uid, gid)| (uid as libc::uid_t, gid as libc::gid_t));

    let (guest_cmd, guest_cmd_args) = split_commandline(&args.command)?;

    if std::env::var_os("LEER_EXEC_PREFLIGHT").is_some() {
        exec_preflight_mmap(sysnrs, &guest_cmd);
    }

    let host_cmd =
        resolve_guest_command_on_host(&guest_cmd, Some(root_dir.as_path())).unwrap_or(guest_cmd);
    seccomp::run_seccomp_forward_to_lkl(
        sysnrs,
        &host_cmd,
        &guest_cmd_args,
        &args.forward_syscall,
        Some(root_dir.as_path()),
        Some(host_workdir.as_path()),
        args.forward_verbose,
        args.root_id || force_root_id,
        id_override,
    )
}

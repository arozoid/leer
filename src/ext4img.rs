//! Directory to ext4 image conversion and caching
//!
//! This module converts a directory to a real ext4 filesystem image
//! to preserve Unix ownership and permissions properly.

use std::collections::hash_map::DefaultHasher;
use std::ffi::OsStr;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Cache entry metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub image_path: PathBuf,
    pub source_hash: u64,
    pub size: u64,
}

/// Calculate a hash of directory contents for cache invalidation
fn calculate_dir_hash(path: &Path) -> io::Result<u64> {
    let mut hasher = DefaultHasher::new();
    
    // Hash the directory path itself
    path.hash(&mut hasher);
    
    // Walk directory and hash mtimes and sizes
    fn hash_dir_recursive(path: &Path, hasher: &mut DefaultHasher) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        
        // Hash file type, mtime, and size
        path.file_name().hash(hasher);
        metadata.modified()?.hash(hasher);
        metadata.len().hash(hasher);
        metadata.permissions().mode().hash(hasher);
        
        if metadata.is_dir() {
            let mut entries: Vec<_> = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
            entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
            
            for entry in entries {
                let entry_path = entry.path();
                hash_dir_recursive(&entry_path, hasher)?;
            }
        }
        
        Ok(())
    }
    
    hash_dir_recursive(path, &mut hasher)?;
    Ok(hasher.finish())
}

/// Calculate required size for ext4 image (with 20% margin)
fn calculate_required_size(path: &Path) -> io::Result<u64> {
    let mut total_size: u64 = 0;
    
    fn calc_size_recursive(path: &Path, total: &mut u64) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        
        // Add file size
        *total += metadata.len();
        
        // Add inode overhead (approx 256 bytes per file)
        *total += 256;
        
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                calc_size_recursive(&entry.path(), total)?;
            }
        }
        
        Ok(())
    }
    
    calc_size_recursive(path, &mut total_size)?;
    
    // Add 20% margin for filesystem overhead
    total_size = (total_size as f64 * 1.2) as u64;
    
    // Minimum size of 64MB
    Ok(total_size.max(64 * 1024 * 1024))
}

/// Create a sparse file of given size
fn create_sparse_file(path: &Path, size: u64) -> io::Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    
    file.set_len(size)?;
    Ok(())
}

/// Create ext4 filesystem on the given device/file
fn create_ext4_filesystem(image_path: &Path) -> Result<(), String> {
    let output = Command::new("mkfs.ext4")
        .arg("-F")  // Force creation even if filesystem exists
        .arg("-E")
        .arg("discard,lazy_itable_init=0,lazy_journal_init=0")  // Disable lazy init for faster creation
        .arg("-O")
        .arg("^metadata_csum")  // Disable metadata checksums for compatibility
        .arg(image_path)
        .output()
        .map_err(|e| format!("Failed to run mkfs.ext4: {e}"))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("mkfs.ext4 failed: {stderr}"));
    }
    
    Ok(())
}

/// Copy directory contents to mounted ext4 image preserving all metadata
fn copy_to_ext4(source: &Path, mount_point: &Path) -> Result<(), String> {
    fn copy_recursive(src: &Path, dst: &Path) -> Result<(), String> {
        let metadata = fs::symlink_metadata(src)
            .map_err(|e| format!("Failed to read metadata for {}: {e}", src.display()))?;
        
        if metadata.is_dir() {
            // Create directory
            fs::create_dir_all(dst)
                .map_err(|e| format!("Failed to create directory {}: {e}", dst.display()))?;
            
            // Copy directory contents
            for entry in fs::read_dir(src)
                .map_err(|e| format!("Failed to read directory {}: {e}", src.display()))? {
                let entry = entry
                    .map_err(|e| format!("Failed to read directory entry: {e}"))?;
                let src_path = entry.path();
                let dst_path = dst.join(entry.file_name());
                copy_recursive(&src_path, &dst_path)?;
            }
        } else if metadata.is_symlink() {
            // Copy symlink
            let target = fs::read_link(src)
                .map_err(|e| format!("Failed to read symlink {}: {e}", src.display()))?;
            std::os::unix::fs::symlink(&target, dst)
                .map_err(|e| format!("Failed to create symlink {} -> {}: {e}", dst.display(), target.display()))?;
        } else {
            // Copy file
            fs::copy(src, dst)
                .map_err(|e| format!("Failed to copy file {} to {}: {e}", src.display(), dst.display()))?;
        }
        
        // Preserve permissions
        let permissions = metadata.permissions();
        fs::set_permissions(dst, permissions)
            .map_err(|e| format!("Failed to set permissions for {}: {e}", dst.display()))?;
        
        // Preserve ownership (requires root or appropriate capabilities)
        let uid = metadata.uid();
        let gid = metadata.gid();
        unsafe {
            let ret = libc::chown(
                dst.as_os_str().as_bytes().as_ptr() as *const i8,
                uid,
                gid,
            );
            if ret != 0 {
                // Ownership preservation failed - this is expected if not root
                // Continue anyway, the files will have current user's ownership
            }
        }
        
        // Preserve timestamps
        let atime = metadata.atime();
        let mtime = metadata.mtime();
        let times = [
            libc::timespec { tv_sec: atime, tv_nsec: metadata.atime_nsec() },
            libc::timespec { tv_sec: mtime, tv_nsec: metadata.mtime_nsec() },
        ];
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                dst.as_os_str().as_bytes().as_ptr() as *const i8,
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            );
        }
        
        Ok(())
    }
    
    // Copy contents of source directory, not the directory itself
    for entry in fs::read_dir(source)
        .map_err(|e| format!("Failed to read source directory {}: {e}", source.display()))? {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {e}"))?;
        let src_path = entry.path();
        let dst_path = mount_point.join(entry.file_name());
        copy_recursive(&src_path, &dst_path)?;
    }
    
    Ok(())
}

/// Get or create cache directory
fn get_cache_dir(custom_cache: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(cache) = custom_cache {
        fs::create_dir_all(cache)?;
        return Ok(cache.to_path_buf());
    }
    
    // Use standard cache location
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("leer");
    fs::create_dir_all(&cache_dir)?;
    Ok(cache_dir)
}

/// Get cached ext4 image path for a source directory
pub fn get_cached_image(
    source_dir: &Path,
    custom_cache: Option<&Path>,
) -> Result<PathBuf, String> {
    let cache_dir = get_cache_dir(custom_cache)
        .map_err(|e| format!("Failed to create cache directory: {e}"))?;
    
    let source_hash = calculate_dir_hash(source_dir)
        .map_err(|e| format!("Failed to calculate directory hash: {e}"))?;
    
    // Create a deterministic filename based on path and hash
    let source_name = source_dir
        .file_name()
        .unwrap_or(OsStr::new("rootfs"))
        .to_string_lossy();
    let cache_name = format!("{}-{:016x}.ext4", source_name, source_hash);
    let image_path = cache_dir.join(&cache_name);
    
    if image_path.exists() {
        eprintln!("Using cached ext4 image: {}", image_path.display());
        return Ok(image_path);
    }
    
    // Create the image
    eprintln!("Creating ext4 image from {}...", source_dir.display());
    
    // Calculate required size
    let required_size = calculate_required_size(source_dir)
        .map_err(|e| format!("Failed to calculate required size: {e}"))?;
    eprintln!("  Required size: {} MB", required_size / 1024 / 1024);
    
    // Create sparse file
    create_sparse_file(&image_path, required_size)
        .map_err(|e| format!("Failed to create image file: {e}"))?;
    
    // Create ext4 filesystem
    create_ext4_filesystem(&image_path)?;
    
    // Mount and copy files
    let temp_mount = tempfile::tempdir()
        .map_err(|e| format!("Failed to create temp mount point: {e}"))?;
    
    // Mount the image
    let mount_output = Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(&image_path)
        .arg(temp_mount.path())
        .output()
        .map_err(|e| format!("Failed to mount image: {e}"))?;
    
    if !mount_output.status.success() {
        let _ = fs::remove_file(&image_path);
        let stderr = String::from_utf8_lossy(&mount_output.stderr);
        return Err(format!("Failed to mount image: {stderr}"));
    }
    
    // Copy files
    let copy_result = copy_to_ext4(source_dir, temp_mount.path());
    
    // Unmount
    let _ = Command::new("umount")
        .arg(temp_mount.path())
        .output();
    
    copy_result?;
    
    // Shrink the image to actual size
    let _ = Command::new("e2fsck")
        .arg("-f")
        .arg("-p")
        .arg(&image_path)
        .output();
    
    let _ = Command::new("resize2fs")
        .arg("-M")
        .arg(&image_path)
        .output();
    
    eprintln!("  Created: {}", image_path.display());
    Ok(image_path)
}

/// Clean up old cached images (keep only recent ones)
pub fn cleanup_cache(custom_cache: Option<&Path>, keep_count: usize) -> Result<(), String> {
    let cache_dir = get_cache_dir(custom_cache)
        .map_err(|e| format!("Failed to access cache directory: {e}"))?;
    
    let mut entries: Vec<_> = fs::read_dir(&cache_dir)
        .map_err(|e| format!("Failed to read cache directory: {e}"))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "ext4")
                .unwrap_or(false)
        })
        .collect();
    
    // Sort by modification time (oldest first)
    entries.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        a_time.cmp(&b_time)
    });
    
    // Remove oldest entries beyond keep_count
    if entries.len() > keep_count {
        for entry in entries.iter().take(entries.len() - keep_count) {
            eprintln!("Removing old cache: {}", entry.path().display());
            let _ = fs::remove_file(entry.path());
        }
    }
    
    Ok(())
}

/// Convert a directory to an ext4 image (for `convert` subcommand)
pub fn run_convert(args: crate::cli::ConvertArgs) -> Result<(), String> {
    let source = &args.source;
    
    if !source.exists() {
        return Err(format!("Source directory does not exist: {}", source.display()));
    }
    if !source.is_dir() {
        return Err(format!("Source path is not a directory: {}", source.display()));
    }
    
    // Determine output path
    let output = match args.output {
        Some(path) => path,
        None => {
            let mut path = source.as_os_str().to_os_string();
            path.push(".ext4");
            PathBuf::from(path)
        }
    };
    
    eprintln!("Converting {} to ext4 image...", source.display());
    eprintln!("  Output: {}", output.display());
    
    // Calculate or use specified size
    let size_bytes = if let Some(size_mb) = args.size_mb {
        (size_mb as u64) * 1024 * 1024
    } else {
        let required = calculate_required_size(source)
            .map_err(|e| format!("Failed to calculate required size: {e}"))?;
        eprintln!("  Required size: {} MB", required / 1024 / 1024);
        required
    };
    
    // Remove existing file if present
    if output.exists() {
        eprintln!("  Removing existing file...");
        fs::remove_file(&output)
            .map_err(|e| format!("Failed to remove existing file: {e}"))?;
    }
    
    // Create sparse file
    eprintln!("  Creating image file ({} MB)...", size_bytes / 1024 / 1024);
    create_sparse_file(&output, size_bytes)
        .map_err(|e| format!("Failed to create image file: {e}"))?;
    
    // Create ext4 filesystem
    eprintln!("  Creating ext4 filesystem...");
    create_ext4_filesystem(&output)?;
    
    // Mount and copy files
    let temp_mount = tempfile::tempdir()
        .map_err(|e| format!("Failed to create temp mount point: {e}"))?;
    
    eprintln!("  Mounting image...");
    let mount_output = Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(&output)
        .arg(temp_mount.path())
        .output()
        .map_err(|e| format!("Failed to mount image: {e}"))?;
    
    if !mount_output.status.success() {
        let _ = fs::remove_file(&output);
        let stderr = String::from_utf8_lossy(&mount_output.stderr);
        return Err(format!("Failed to mount image: {stderr}"));
    }
    
    eprintln!("  Copying files...");
    let copy_result = copy_to_ext4(source, temp_mount.path());
    
    // Unmount
    eprintln!("  Unmounting...");
    let _ = Command::new("umount")
        .arg(temp_mount.path())
        .output();
    
    copy_result?;
    
    // Shrink the image to actual size
    eprintln!("  Optimizing image size...");
    let _ = Command::new("e2fsck")
        .arg("-f")
        .arg("-p")
        .arg(&output)
        .output();
    
    let _ = Command::new("resize2fs")
        .arg("-M")
        .arg(&output)
        .output();
    
    // Get final size
    let final_size = fs::metadata(&output)
        .map(|m| m.len())
        .unwrap_or(0);
    
    eprintln!("  Done! Final size: {} MB", final_size / 1024 / 1024);
    eprintln!("  Image created: {}", output.display());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    
    #[test]
    fn test_calculate_dir_hash() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        
        let hash1 = calculate_dir_hash(temp_dir.path()).unwrap();
        let hash2 = calculate_dir_hash(temp_dir.path()).unwrap();
        assert_eq!(hash1, hash2, "Same directory should produce same hash");
        
        // Modify file
        file.write_all(b"more content").unwrap();
        drop(file);
        
        let hash3 = calculate_dir_hash(temp_dir.path()).unwrap();
        assert_ne!(hash1, hash3, "Modified directory should produce different hash");
    }
    
    #[test]
    fn test_calculate_required_size() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some files
        for i in 0..10 {
            let file_path = temp_dir.path().join(format!("file{}.txt", i));
            let mut file = fs::File::create(&file_path).unwrap();
            file.write_all(&vec![0u8; 1024]).unwrap();
        }
        
        let size = calculate_required_size(temp_dir.path()).unwrap();
        assert!(size >= 64 * 1024 * 1024, "Should have minimum size of 64MB");
        assert!(size > 10 * 1024, "Should account for file sizes");
    }
}

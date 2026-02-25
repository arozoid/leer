use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

mod host;
mod image;
mod lkl;
mod syscall;
mod seccomp;

/// CLI argument definitions used by the `host` and `image` subcommands.
pub mod cli {
    use super::*;

    #[derive(Args, Debug, Clone)]
    pub struct HostArgs {
        /// Root directory to expose via virtio-fs (host path)
        #[arg(short = 'r', long = "root-dir")]
        pub root_dir: Option<PathBuf>,

        /// Root directory with recommended mounts (/proc, /dev, /dev/pts, /sys, etc.)
        #[arg(short = 'R', long = "recommended-root", conflicts_with_all = ["root_dir", "system_root"])]
        pub recommended_root: Option<PathBuf>,

        /// Root directory with recommended mounts and root identity (uid/gid 0)
        #[arg(short = 'S', long = "system-root", conflicts_with_all = ["root_dir", "recommended_root"])]
        pub system_root: Option<PathBuf>,

        /// Working directory inside the guest (defaults to --root-dir value)
        #[arg(short = 'w', long = "work-dir")]
        pub work_dir: Option<PathBuf>,

        /// Command to execute inside the mounted rootfs
        #[arg(short = 'c', long = "command", default_value = "/bin/sh")]
        pub command: String,

        /// Kernel command-line parameters
        #[arg(short = 'k', long = "cmdline", default_value = "mem=1024M loglevel=4")]
        pub cmdline: String,

        /// Mount options passed to virtiofs (repeatable, joined with commas)
        #[arg(short = 'm', long = "mount-opts")]
        pub mount_opt: Vec<String>,

        /// Bind-mount specification (SRC:DST, repeatable)
        #[arg(short = 'b', long = "bind-mount")]
        pub bind: Vec<String>,

        /// Force root identity (uid 0, gid 0) inside the guest
        #[arg(long = "root-id", default_value_t = false)]
        pub root_id: bool,

        /// Change identity to match the host user inside the guest
        #[arg(long = "change-id", default_value_t = false)]
        pub change_id: bool,

        /// Syscall names/numbers to forward (advanced)
        #[arg(long = "forward-syscall")]
        pub forward_syscall: Vec<String>,

        /// Print verbose forwarding diagnostics
        #[arg(long = "forward-verbose", default_value_t = false)]
        pub forward_verbose: bool,
    }

    #[derive(Args, Debug, Clone)]
    pub struct ImageArgs {
        /// Rootfs image file path
        #[arg(short = 'r', long = "root-dir")]
        pub root_dir: Option<PathBuf>,

        /// Rootfs image with recommended mounts (/proc, /dev, /dev/pts, /sys, etc.)
        #[arg(short = 'R', long = "recommended-root", conflicts_with_all = ["root_dir", "system_root"])]
        pub recommended_root: Option<PathBuf>,

        /// Rootfs image with recommended mounts and root identity (uid/gid 0)
        #[arg(short = 'S', long = "system-root", conflicts_with_all = ["root_dir", "recommended_root"])]
        pub system_root: Option<PathBuf>,

        /// Filesystem type inside the image
        #[arg(short = 't', long = "fs-type", default_value = "ext4")]
        pub fs_type: String,

        /// Partition number (0 = whole disk)
        #[arg(short = 'p', long = "part", default_value_t = 0)]
        pub part: u32,

        /// Working directory inside the guest (defaults to /)
        #[arg(short = 'w', long = "work-dir", default_value = "/")]
        pub work_dir: String,

        /// Command to execute inside the mounted rootfs
        #[arg(short = 'c', long = "command", default_value = "/bin/sh")]
        pub command: String,

        /// Kernel command-line parameters
        #[arg(short = 'k', long = "cmdline", default_value = "mem=1024M loglevel=4")]
        pub cmdline: String,

        /// Mount options (repeatable, joined with commas)
        #[arg(short = 'm', long = "mount-opts")]
        pub mount_opt: Vec<String>,

        /// Bind-mount specification (SRC:DST, repeatable)
        #[arg(short = 'b', long = "bind-mount")]
        pub bind: Vec<String>,

        /// Force root identity (uid 0, gid 0) inside the guest
        #[arg(long = "root-id", default_value_t = false)]
        pub root_id: bool,

        /// Change identity to match the host user inside the guest
        #[arg(long = "change-id", default_value_t = false)]
        pub change_id: bool,

        /// Syscall names/numbers to forward (advanced)
        #[arg(long = "forward-syscall")]
        pub forward_syscall: Vec<String>,

        /// Print verbose forwarding diagnostics
        #[arg(long = "forward-verbose", default_value_t = false)]
        pub forward_verbose: bool,
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "LKL runtime with virtio-fs and rootfs image boot modes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Boot a Linux kernel and mount a host directory via virtio-fs
    Host(cli::HostArgs),
    /// Boot a Linux kernel from a rootfs disk image
    Image(cli::ImageArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Host(args) => host::run_host(args),
        Commands::Image(args) => image::run_image(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

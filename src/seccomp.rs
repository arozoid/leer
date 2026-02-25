use std::path::Path;
use std::process::Command;

use crate::syscall::SysNrs;

pub(crate) fn run_seccomp_forward_to_lkl(
    _sysnrs: &SysNrs,
    host_cmd: &str,
    command_args: &[String],
    _forward_syscall: &[String],
    _host_root: Option<&Path>,
    host_workdir: Option<&Path>,
    _forward_verbose: bool,
) -> Result<(), String> {
    let mut cmd = Command::new(host_cmd);
    cmd.args(command_args);
    if let Some(workdir) = host_workdir {
        cmd.current_dir(workdir);
    }

    let status = cmd
        .status()
        .map_err(|e| format!("failed to execute host command '{host_cmd}': {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "host command exited unsuccessfully: '{}' status={status}",
            host_cmd
        ))
    }
}

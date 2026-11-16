//! App-mode environment (PoE OS Phase 1, shell-independent):
//! where the suite's data lives on each desktop OS, where the
//! local control endpoint is, and the service definition a shell
//! or an installer needs to run the node as a user service.
//!
//! These conventions exist so the desktop shell — whichever
//! technology the owners choose for it — never has to invent
//! them: it resolves the data directory here, starts the node
//! against it (directly, or through the generated user-service
//! unit), waits for the control endpoint to answer `status`,
//! and talks to the node only through that endpoint.
//!
//! Resolution order for the data directory: an explicit `--dir`
//! (the testnet's existing flag) always wins for a run; the
//! app-mode default below is what `poe-node paths` reports and
//! what an installer uses when nothing was specified. `POE_DIR`
//! overrides the app-mode default (portable installs, tests).

use std::path::PathBuf;

/// The app-mode data directory for this platform, honouring
/// `POE_DIR`. Per-OS conventions: Linux follows the XDG base
/// directory spec, macOS the Application Support folder,
/// Windows the per-user local app data folder.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("POE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    platform_data_dir()
}

#[cfg(target_os = "macos")]
fn platform_data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library").join("Application Support").join("PoE Node")
}

#[cfg(windows)]
fn platform_data_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("APPDATA"))
        .unwrap_or_default();
    PathBuf::from(base).join("PoE Node")
}

#[cfg(not(any(target_os = "macos", windows)))]
fn platform_data_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("poe-node");
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".local").join("share").join("poe-node")
}

/// The node's local control endpoint for a data directory: the
/// Unix socket the control surface already serves on Unix; the
/// named pipe a Windows build will serve (Phase 1 shell work —
/// the name is fixed here so the shell can rely on it).
pub fn control_endpoint(dir: &std::path::Path) -> String {
    #[cfg(windows)]
    {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "node".to_string());
        format!(r"\\.\pipe\poe-node-{name}")
    }
    #[cfg(not(windows))]
    {
        dir.join("control.sock").to_string_lossy().into_owned()
    }
}

/// A systemd **user** unit running the node as the suite's
/// service (Linux app-mode). The shell can install this verbatim
/// under `~/.config/systemd/user/poe-node.service`, or supervise
/// the same command line itself — the unit is the contract, not
/// the only way to honour it. `Restart=on-failure` plus the
/// node's own resume discipline (finstate → bundle → refuse)
/// make restarts safe; `POE_VAULT` is passed through when the
/// caller sets it, so the custody choice stays the operator's.
pub fn systemd_user_unit(exe: &std::path::Path, dir: &std::path::Path) -> String {
    let vault_line = match std::env::var("POE_VAULT") {
        Ok(v) if !v.is_empty() => format!("Environment=POE_VAULT={v}\n"),
        _ => String::new(),
    };
    format!(
        "[Unit]\n\
         Description=PoE node (suite service, app-mode)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} testnet --dir {dir}\n\
         {vault_line}\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = exe.display(),
        dir = dir.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Env-mutating cases run inside one test function: process
    /// environment is shared across parallel tests.
    #[test]
    fn data_dir_resolution_order() {
        // POE_DIR wins over everything.
        std::env::set_var("POE_DIR", "/tmp/poe-appenv-probe");
        assert_eq!(data_dir(), PathBuf::from("/tmp/poe-appenv-probe"));
        std::env::remove_var("POE_DIR");

        #[cfg(not(any(target_os = "macos", windows)))]
        {
            // XDG_DATA_HOME is honoured on Linux; HOME is the base
            // of the fallback.
            std::env::set_var("XDG_DATA_HOME", "/tmp/poe-xdg-probe");
            assert_eq!(data_dir(), PathBuf::from("/tmp/poe-xdg-probe/poe-node"));
            std::env::remove_var("XDG_DATA_HOME");
            let home = std::env::var("HOME").unwrap();
            assert_eq!(
                data_dir(),
                PathBuf::from(home).join(".local").join("share").join("poe-node")
            );
        }
    }

    #[test]
    fn control_endpoint_names() {
        let dir = PathBuf::from("/some/where/node1");
        let ep = control_endpoint(&dir);
        #[cfg(windows)]
        assert_eq!(ep, r"\\.\pipe\poe-node-node1");
        #[cfg(not(windows))]
        assert_eq!(ep, "/some/where/node1/control.sock");
    }

    #[test]
    fn unit_carries_the_contract() {
        let unit = systemd_user_unit(
            std::path::Path::new("/opt/poe/poe-node"),
            std::path::Path::new("/home/x/.local/share/poe-node"),
        );
        assert!(unit.contains("ExecStart=/opt/poe/poe-node testnet --dir /home/x/.local/share/poe-node"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }
}

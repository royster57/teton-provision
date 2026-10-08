//! `teton-device`: provisioning daemon and maintenance commands (SPEC.md §9.1).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(version, about = "Teton device: Wi-Fi provisioning over BLE")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the provisioning daemon.
    Run(RunArgs),
    /// Print the device label QR code to the terminal.
    Label {
        #[arg(long, default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Forget the provisioned network and return to the unprovisioned state (root).
    Reset {
        /// Also delete the device key and label (development only).
        #[arg(long)]
        new_identity: bool,
        #[arg(long, default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Advertise for re-provisioning for a limited window (root).
    Reprovision,
}

const DEFAULT_STATE_DIR: &str = "/var/lib/teton-provision";

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// Log to the terminal and print the label QR on startup.
    #[arg(long)]
    foreground: bool,
    #[arg(long, value_enum, default_value_t = WifiMode::Nm)]
    wifi: WifiMode,
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    /// Write JSON-lines events (no secrets) to this file.
    #[arg(long)]
    event_log: Option<PathBuf>,
    /// Base URL the label QR points to.
    #[arg(long, default_value = "https://royster57.github.io/teton-provision/")]
    label_base_url: String,
    #[arg(long, value_parser = parse_duration, default_value = "600s")]
    recovery_after: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "30s")]
    join_timeout: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    idle_timeout: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "600s")]
    manual_window: Duration,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum WifiMode {
    /// NetworkManager over D-Bus.
    Nm,
    /// Scripted backend for tests and demos without touching the network.
    Simulated,
}

/// Parses `90`, `90s` or `10m`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, mult) = match s.strip_suffix('m') {
        Some(n) => (n, 60),
        None => (s.strip_suffix('s').unwrap_or(s), 1),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .map(Duration::from_secs)
        .ok_or_else(|| format!("invalid duration {s:?} (expected e.g. 90s or 10m)"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(_) => bail!("`run` is not implemented yet"),
        Command::Label { .. } => bail!("`label` is not implemented yet"),
        Command::Reset { .. } => bail!("`reset` is not implemented yet"),
        Command::Reprovision => bail!("`reprovision` is not implemented yet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("10m"), Ok(Duration::from_secs(600)));
        assert!(parse_duration("ten").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn cli_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}

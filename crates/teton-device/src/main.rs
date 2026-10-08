//! `teton-device`: provisioning daemon and maintenance commands (SPEC.md §9.1).

use std::path::PathBuf;
use std::time::Duration;

use std::sync::Arc;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use teton_device::ble::Peripheral;
use teton_device::device::{Control, Device, Timers};
use teton_device::wifi::sim::{self, SimWifi};
use teton_device::wifi::{self, nm::NmWifi};
use teton_device::{identity, label};
use teton_proto::label::format_id;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tracing::{info, warn};

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
        Command::Run(args) => tokio::runtime::Runtime::new()?.block_on(run(args)),
        Command::Label { state_dir } => print_label(&state_dir),
        Command::Reset {
            new_identity,
            state_dir,
        } => tokio::runtime::Runtime::new()?.block_on(reset(&state_dir, new_identity)),
        Command::Reprovision => reprovision(),
    }
}

fn init_logging(event_log: Option<&std::path::Path>) -> Result<()> {
    use tracing_subscriber::prelude::*;
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    // stderr goes to the terminal in the foreground and to the journal under systemd.
    let stderr = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let events = match event_log {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            Some(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::sync::Mutex::new(file)),
            )
        }
        None => None,
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(stderr)
        .with(events)
        .init();
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    init_logging(args.event_log.as_deref())?;
    let identity = identity::load_or_create(&args.state_dir, &args.label_base_url)?;
    let id = identity.label.id.clone();
    info!(id = %format_id(&id), url = %identity.url, "device identity");
    let qr = label::write_files(&args.state_dir, &identity.url, &id)?;
    if args.foreground {
        eprintln!(
            "\n{}  Teton device {}  (label: {})\n",
            qr.to_terminal(),
            format_id(&id),
            args.state_dir.join("label.svg").display()
        );
    }

    let (control_tx, control_rx) = unbounded_channel();
    tokio::spawn(forward_signals(control_tx));

    let (radio, radio_events) = Peripheral::start(format!("Teton-{id}")).await?;
    let timers = Timers {
        recovery_after: args.recovery_after,
        idle_timeout: args.idle_timeout,
        manual_window: args.manual_window,
        ..Timers::default()
    };
    let key = Arc::new(identity.key);
    match args.wifi {
        WifiMode::Nm => {
            let wifi = Arc::new(NmWifi::connect(None, args.join_timeout).await?);
            Device::new(key, id, wifi, radio, timers)
                .run(radio_events, control_rx)
                .await
        }
        WifiMode::Simulated => {
            warn!(
                password = sim::PASSWORD,
                "SIMULATED Wi-Fi: no real network is touched"
            );
            let wifi = Arc::new(SimWifi::default());
            Device::new(key, id, wifi, radio, timers)
                .run(radio_events, control_rx)
                .await
        }
    }
}

/// Prints the label QR from `label.json`; works for any user (no key access).
fn print_label(state_dir: &std::path::Path) -> Result<()> {
    let path = state_dir.join(identity::LABEL_FILE);
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("{}: {e} (has the daemon run yet?)", path.display()))?,
    )?;
    let (Some(url), Some(id)) = (doc["url"].as_str(), doc["id"].as_str()) else {
        bail!("{} is malformed", path.display());
    };
    let qr = label::Matrix::encode(url)?;
    println!(
        "\n{}  Teton device {}\n  {url}\n",
        qr.to_terminal(),
        format_id(id)
    );
    Ok(())
}

const SERVICE: &str = "teton-provisiond.service";

fn service_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", SERVICE])
        .status()
        .is_ok_and(|s| s.success())
}

/// Forgets the provisioned network. A running daemon notices on its next
/// status poll (within 5 s) and starts advertising; no restart needed.
async fn reset(state_dir: &std::path::Path, new_identity: bool) -> Result<()> {
    let wifi = NmWifi::connect(None, Duration::from_secs(30)).await?;
    let mut deleted = 0;
    for id in [wifi::PROFILE_ID, wifi::CANDIDATE_ID] {
        for path in wifi.profiles_named(id).await? {
            wifi.delete_profile(&path)
                .await
                .map_err(|e| anyhow::anyhow!("deleting {id}: {e:#} (try with sudo)"))?;
            deleted += 1;
        }
    }
    println!("Deleted {deleted} provisioned Wi-Fi profile(s); the device is unprovisioned.");
    if new_identity {
        for f in [
            identity::KEY_FILE,
            identity::LABEL_FILE,
            "label.png",
            "label.svg",
        ] {
            match std::fs::remove_file(state_dir.join(f)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => bail!(
                    "removing {}: {e} (try with sudo)",
                    state_dir.join(f).display()
                ),
            }
        }
        println!("Device identity deleted: the old label no longer works.");
        if service_active() {
            let ok = std::process::Command::new("systemctl")
                .args(["restart", SERVICE])
                .status()?
                .success();
            if !ok {
                bail!("could not restart {SERVICE}");
            }
            println!(
                "Restarted {SERVICE} with a new identity; print it with `teton-device label`."
            );
        } else {
            println!("A new identity is created when the daemon next starts.");
        }
    }
    Ok(())
}

/// Opens the manual re-provisioning window by sending SIGUSR1 to the daemon:
/// the systemd service if it is running, otherwise a foreground `run`.
fn reprovision() -> Result<()> {
    let signal = |args: &[&str]| -> Result<()> {
        let ok = std::process::Command::new(args[0])
            .args(&args[1..])
            .status()?
            .success();
        if !ok {
            bail!("`{}` failed (try with sudo)", args.join(" "));
        }
        Ok(())
    };
    if service_active() {
        signal(&[
            "systemctl",
            "kill",
            "--kill-whom=main",
            "--signal=SIGUSR1",
            SERVICE,
        ])?;
    } else {
        let me = std::process::id().to_string();
        let mut found = false;
        for entry in std::fs::read_dir("/proc")?.flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
            let is_daemon = args.first().is_some_and(|a| a.ends_with(b"teton-device"))
                && args.get(1) == Some(&b"run".as_slice());
            if is_daemon && pid != me {
                signal(&["kill", "-USR1", &pid])?;
                found = true;
            }
        }
        if !found {
            bail!("no running teton-device daemon found");
        }
    }
    println!("Re-provisioning window opened: the device advertises for the next 10 minutes.");
    Ok(())
}

/// SIGUSR1 opens a re-provisioning window; SIGINT/SIGTERM stop the daemon.
async fn forward_signals(tx: UnboundedSender<Control>) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    loop {
        let c = tokio::select! {
            _ = usr1.recv() => Control::Reprovision,
            _ = term.recv() => Control::Shutdown,
            _ = int.recv() => Control::Shutdown,
        };
        let stop = matches!(c, Control::Shutdown);
        if tx.send(c).is_err() || stop {
            return Ok(());
        }
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

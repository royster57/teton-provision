//! M2 hardware probe for the NetworkManager backend. Not part of the product.
//!
//! ```sh
//! cargo run -p teton-device --example nm_probe -- scan
//! cargo run -p teton-device --example nm_probe -- join roy        # prompts for the password
//! cargo run -p teton-device --example nm_probe -- cleanup
//! ```
//!
//! Every command returns only once the Wi-Fi device is connected again (or
//! after 90 s), so a session that depends on this laptop's network survives.

use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};
use teton_device::wifi::nm::NmWifi;
use teton_device::wifi::{CANDIDATE_ID, PROFILE_ID, WifiBackend, consts::STATE_ACTIVATED};
use teton_proto::msg::{JoinRequest, Secret, Security};

#[derive(Parser)]
struct Cli {
    /// Wi-Fi interface (default: first Wi-Fi device).
    #[arg(long)]
    iface: Option<String>,
    #[arg(long, default_value_t = 30)]
    join_timeout: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan and list networks as the phone would see them.
    Scan,
    /// Show the active profile and NM's connectivity verdict.
    Status,
    /// Join a network through the real provisioning code path.
    Join {
        ssid: String,
        /// Open network: don't prompt for a password.
        #[arg(long)]
        open: bool,
        /// Hidden network; requires --sec.
        #[arg(long)]
        hidden: bool,
        #[arg(long, value_parser = ["wpa2", "wpa3", "open"])]
        sec: Option<String>,
    },
    /// Delete teton-provisioned profiles so the laptop returns to its own networks.
    Cleanup,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,teton_device=debug".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let wifi = NmWifi::connect(cli.iface.as_deref(), Duration::from_secs(cli.join_timeout)).await?;

    match cli.cmd {
        Cmd::Scan => {
            let mut aps = wifi.scan_aps(true).await?;
            aps.sort_by_key(|a| std::cmp::Reverse(a.network.signal));
            println!(
                "{:<34} {:>6}  {:<11} key-mgmt",
                "SSID", "signal", "security"
            );
            for a in &aps {
                println!(
                    "{:<34} {:>6}  {:<11} {}",
                    format!("{:?}", a.network.ssid),
                    a.network.signal,
                    serde_json::to_string(&a.network.sec)?.trim_matches('"'),
                    a.security.key_mgmt.unwrap_or("-")
                );
            }
            println!(
                "\nAs sent to the phone ({} entries):",
                wifi.scan().await?.len()
            );
            println!("{}", serde_json::to_string(&wifi.scan().await?)?);
        }
        Cmd::Status => print_status(&wifi).await?,
        Cmd::Join {
            ssid,
            open,
            hidden,
            sec,
        } => {
            let psk = if open {
                None
            } else {
                Some(Secret::new(rpassword::prompt_password(format!(
                    "Password for {ssid:?}: "
                ))?))
            };
            let sec = sec
                .map(|s| serde_json::from_value::<Security>(s.into()))
                .transpose()?;
            let req = JoinRequest {
                ssid,
                psk,
                sec,
                hidden,
            };
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let start = Instant::now();
            let printer = tokio::spawn(async move {
                while let Some(p) = rx.recv().await {
                    println!("[{:>5.1}s] progress: {p:?}", start.elapsed().as_secs_f32());
                }
            });
            let result = wifi.join(&req, tx).await;
            printer.await?;
            match result {
                Ok(j) => println!(
                    "[{:>5.1}s] RESULT: joined, ip={} internet={:?}",
                    start.elapsed().as_secs_f32(),
                    j.ip,
                    j.internet
                ),
                Err(f) => println!(
                    "[{:>5.1}s] RESULT: failed, reason={:?} ({})",
                    start.elapsed().as_secs_f32(),
                    f.reason,
                    f.detail
                ),
            }
            wait_online(&wifi).await?;
        }
        Cmd::Cleanup => {
            for id in [PROFILE_ID, CANDIDATE_ID] {
                for p in wifi.profiles_named(id).await? {
                    wifi.delete_profile(&p).await?;
                    println!("deleted {id} ({p})");
                }
            }
            wait_online(&wifi).await?;
        }
    }
    Ok(())
}

async fn print_status(wifi: &NmWifi) -> Result<()> {
    match wifi.active_profile().await? {
        Some((id, _)) => println!("{}: active profile {id:?}", wifi.iface),
        None => println!("{}: no active profile", wifi.iface),
    }
    println!("connectivity: {:?}", wifi.connectivity().await);
    Ok(())
}

/// Waits until the Wi-Fi device is activated on any profile.
async fn wait_online(wifi: &NmWifi) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(90) {
        if wifi.device_state().await? == STATE_ACTIVATED {
            print_status(wifi).await?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!("WARNING: still offline after 90 s; run `nmcli connection up roy`");
    Ok(())
}

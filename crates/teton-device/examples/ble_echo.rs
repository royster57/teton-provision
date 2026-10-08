//! M3 hardware check for the BLE pipe. Not part of the product.
//!
//! ```sh
//! cargo run -p teton-device --example ble_echo -- --state-dir ./state
//! ```
//!
//! Reassembles chunked messages written to `rx` and answers on `tx`:
//! `big` → a 600-byte message (tests chunking at the real MTU),
//! anything else → `echo:<message>`. From nRF Connect, write the byte array
//! `806869` (FINAL chunk, "hi") and expect the notification `806563686f3a6869`.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use teton_device::ble::{Inbound, Peripheral};
use teton_device::identity;
use teton_proto::frame::{Reassembler, chunk, chunk_len_for_mtu};
use teton_proto::hex;
use teton_proto::label::format_id;
use tracing::{info, warn};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "./state")]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,teton_device=debug,ble_echo=debug".into()),
        )
        .init();
    let cli = Cli::parse();
    let id = identity::load_or_create(
        &cli.state_dir,
        "https://royster57.github.io/teton-provision/",
    )?;
    let name = format!("Teton-{}", id.label.id);
    let (mut ble, mut inbound) = Peripheral::start(name.clone()).await?;
    ble.set_advertising(true).await?;
    info!(
        "device {} is advertising as {name:?}; Ctrl-C to stop",
        format_id(&id.label.id)
    );

    let mut reassembler = Reassembler::new();
    let mut owner = None;
    loop {
        let event = tokio::select! {
            e = inbound.recv() => match e { Some(e) => e, None => break },
            _ = tokio::signal::ctrl_c() => break,
        };
        match event {
            Inbound::Subscribed => info!("phone subscribed to tx"),
            Inbound::Disconnected(addr) => {
                info!(%addr, "phone disconnected");
                if owner == Some(addr) {
                    owner = None;
                    reassembler = Reassembler::new();
                    ble.set_advertising(true).await?;
                }
            }
            Inbound::Write {
                from,
                mtu,
                chunk: c,
            } => {
                info!(%from, mtu, len = c.len(), bytes = %hex(&c), "chunk received");
                if owner.is_none() {
                    owner = Some(from);
                    ble.set_advertising(false).await?; // one session at a time
                } else if owner != Some(from) {
                    warn!(%from, "second central; disconnecting it");
                    let _ = ble.disconnect(from).await;
                    continue;
                }
                let msg = match reassembler.push(&c) {
                    Ok(Some(m)) => m,
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(error = %e, "framing error");
                        continue;
                    }
                };
                let text = String::from_utf8_lossy(&msg);
                info!(len = msg.len(), message = %text, "message received");
                let reply = if text == "big" {
                    (0..600).map(|i| b'0' + (i % 10) as u8).collect()
                } else {
                    [b"echo:".as_slice(), &msg].concat()
                };
                let chunks = chunk(&reply, chunk_len_for_mtu(mtu))?;
                info!(
                    len = reply.len(),
                    chunks = chunks.len(),
                    chunk_len = chunk_len_for_mtu(mtu),
                    "replying"
                );
                for c in chunks {
                    if let Err(e) = ble.notify(c).await {
                        warn!(error = %e, "notify failed");
                        break;
                    }
                }
            }
        }
    }
    info!("stopping");
    Ok(())
}

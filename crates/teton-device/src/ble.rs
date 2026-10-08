//! BLE peripheral: one GATT service with an `rx` (write) and a `tx` (notify)
//! characteristic, used as a chunked message pipe (SPEC.md §4).
//!
//! This layer only moves chunks. Framing, sessions and crypto live above it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bluer::adv::{Advertisement, AdvertisementHandle};
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicNotifier, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use bluer::{Adapter, Address, DeviceEvent, DeviceProperty, Uuid};
use futures::{FutureExt, StreamExt};
use teton_proto::gatt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{debug, info, warn};

/// Something the phone did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// One chunk written to `rx`. `mtu` is the ATT MTU negotiated with `from`.
    Write {
        from: Address,
        mtu: u16,
        chunk: Vec<u8>,
    },
    /// A central subscribed to `tx` notifications.
    Subscribed,
    /// A central that had written to us disconnected.
    Disconnected(Address),
}

pub struct Peripheral {
    _session: bluer::Session,
    adapter: Adapter,
    _app: ApplicationHandle,
    adv: Option<AdvertisementHandle>,
    name: String,
    notifier: Arc<tokio::sync::Mutex<Option<CharacteristicNotifier>>>,
}

fn uuid(s: &str) -> Uuid {
    s.parse().expect("valid UUID constant")
}

impl Peripheral {
    /// Registers the GATT application on the default adapter. Advertising is
    /// off until [`Peripheral::set_advertising`] turns it on.
    pub async fn start(name: String) -> Result<(Self, UnboundedReceiver<Inbound>)> {
        let session = bluer::Session::new().await.context("connecting to BlueZ")?;
        let adapter = session
            .default_adapter()
            .await
            .context("no Bluetooth adapter")?;
        adapter
            .set_powered(true)
            .await
            .context("powering on the adapter")?;
        info!(adapter = adapter.name(), address = %adapter.address().await?, "Bluetooth adapter ready");

        let (tx, rx) = unbounded_channel();
        let notifier = Arc::new(tokio::sync::Mutex::new(None));
        let watched = Arc::new(Mutex::new(HashSet::new()));

        let write_tx = tx.clone();
        let write_adapter = adapter.clone();
        let on_write: bluer::gatt::local::CharacteristicWriteFun = Box::new(move |chunk, req| {
            let tx = write_tx.clone();
            let from = req.device_address;
            // Watch each writer once, so a disconnect ends its session.
            if watched.lock().expect("lock").insert(from) {
                spawn_disconnect_watch(write_adapter.clone(), from, tx.clone(), watched.clone());
            }
            let _ = tx.send(Inbound::Write {
                from,
                mtu: req.mtu,
                chunk,
            });
            async { Ok(()) }.boxed()
        });

        let notify_slot = notifier.clone();
        let notify_tx = tx.clone();
        let on_subscribe: bluer::gatt::local::CharacteristicNotifyFun = Box::new(move |n| {
            let slot = notify_slot.clone();
            let tx = notify_tx.clone();
            async move {
                debug!(confirming = n.confirming(), "tx subscribed");
                *slot.lock().await = Some(n);
                let _ = tx.send(Inbound::Subscribed);
            }
            .boxed()
        });

        let app = Application {
            services: vec![Service {
                uuid: uuid(gatt::SERVICE),
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: uuid(gatt::RX),
                        write: Some(CharacteristicWrite {
                            write: true,
                            method: CharacteristicWriteMethod::Fun(on_write),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: uuid(gatt::TX),
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Fun(on_subscribe),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app = adapter
            .serve_gatt_application(app)
            .await
            .context("registering the GATT application")?;
        Ok((
            Self {
                _session: session,
                adapter,
                _app: app,
                adv: None,
                name,
                notifier,
            },
            rx,
        ))
    }

    /// Starts or stops advertising `Teton-<id>` with the provisioning service.
    pub async fn set_advertising(&mut self, on: bool) -> Result<()> {
        match (on, self.adv.is_some()) {
            (true, false) => {
                let adv = Advertisement {
                    service_uuids: [uuid(gatt::SERVICE)].into(),
                    local_name: Some(self.name.clone()),
                    discoverable: Some(true),
                    ..Default::default()
                };
                self.adv = Some(
                    self.adapter
                        .advertise(adv)
                        .await
                        .context("starting advertising")?,
                );
                info!(name = %self.name, "advertising");
            }
            (false, true) => {
                self.adv = None; // dropping the handle unregisters the advertisement
                info!("advertising stopped");
            }
            _ => {}
        }
        Ok(())
    }

    /// Sends one chunk as a `tx` notification. BlueZ delivers it to every
    /// subscribed central; chunks must fit in `MTU − 3`.
    pub async fn notify(&self, chunk: Vec<u8>) -> Result<()> {
        let mut slot = self.notifier.lock().await;
        let n = slot.as_mut().context("no central subscribed to tx")?;
        if n.is_stopped() {
            *slot = None;
            anyhow::bail!("tx subscription stopped");
        }
        n.notify(chunk).await.context("sending notification")?;
        Ok(())
    }

    /// Disconnects a central.
    pub async fn disconnect(&self, addr: Address) -> Result<()> {
        self.adapter.device(addr)?.disconnect().await?;
        Ok(())
    }
}

fn spawn_disconnect_watch(
    adapter: Adapter,
    addr: Address,
    tx: UnboundedSender<Inbound>,
    watched: Arc<Mutex<HashSet<Address>>>,
) {
    tokio::spawn(async move {
        let events = async { adapter.device(addr)?.events().await };
        match events.await {
            Ok(mut events) => {
                while let Some(DeviceEvent::PropertyChanged(p)) = events.next().await {
                    if matches!(p, DeviceProperty::Connected(false)) {
                        let _ = tx.send(Inbound::Disconnected(addr));
                        break;
                    }
                }
            }
            Err(e) => warn!(%addr, error = %e, "cannot watch for disconnect"),
        }
        watched.lock().expect("lock").remove(&addr);
    });
}

//! Teton BLE provisioning protocol (SPEC.md §3–§6).
//!
//! Pure protocol logic shared by the device daemon and the loopback tests:
//! no I/O, no async.

/// Protocol version carried in `hello` / `challenge` and in the label URL.
pub const PROTOCOL_VERSION: u8 = 1;

/// GATT service and characteristic UUIDs (SPEC.md §4).
pub mod gatt {
    /// Provisioning service.
    pub const SERVICE: &str = "a08f8d5d-8e67-44f2-89d9-59299eab3f49";
    /// Phone → device, write with response.
    pub const RX: &str = "4b11a607-2abe-4fc6-9b03-e62677c327fe";
    /// Device → phone, notify.
    pub const TX: &str = "d5c6dde2-10f8-435c-90cb-c1e003a5550c";
}

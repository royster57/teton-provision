//! Checks the Rust implementation against `tests/test-vectors.json`, the
//! contract shared with the JS configurator.

use serde_json::Value;
use teton_proto::crypto::{Channel, KeyPair, derive_session_keys, hkdf_info};
use teton_proto::frame::{Reassembler, chunk};
use teton_proto::label::{Label, format_id};
use teton_proto::msg::{self, DeviceMsg, PhoneMsg};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/test-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn session() {
    let v = &vectors()["session"];
    let device = KeyPair::from_scalar(&unhex(&v["device_private"])).unwrap();
    let eph = KeyPair::from_scalar(&unhex(&v["ephemeral_private"])).unwrap();
    assert_eq!(device.public_key().to_vec(), unhex(&v["device_public"]));
    assert_eq!(eph.public_key().to_vec(), unhex(&v["ephemeral_public"]));
    let id = v["device_id"].as_str().unwrap();
    assert_eq!(teton_proto::label::device_id(device.public_key()), id);
    let nonce = unhex(&v["nonce"]);

    let z = eph.agree(device.public_key()).unwrap();
    assert_eq!(z.to_vec(), unhex(&v["shared_secret"]));
    assert_eq!(*device.agree(eph.public_key()).unwrap(), *z);
    assert_eq!(
        hkdf_info(id, eph.public_key(), device.public_key()),
        unhex(&v["hkdf_info"])
    );
    let keys = derive_session_keys(&*z, &nonce, id, eph.public_key(), device.public_key()).unwrap();
    assert_eq!(keys.phone_to_device.to_vec(), unhex(&v["k_pd"]));
    assert_eq!(keys.device_to_phone.to_vec(), unhex(&v["k_dp"]));

    let mut phone = Channel::initiate(&eph, device.public_key(), id, &nonce).unwrap();
    let mut dev = Channel::accept(&device, id, &nonce, eph.public_key()).unwrap();
    for m in v["phone_to_device"].as_array().unwrap() {
        let pt = m["plaintext"].as_str().unwrap().as_bytes();
        let ct = unhex(&m["ciphertext"]);
        assert_eq!(phone.seal(pt).unwrap(), ct);
        assert_eq!(&*dev.open(&ct).unwrap(), pt);
        msg::decode::<PhoneMsg>(pt).unwrap();
    }
    for m in v["device_to_phone"].as_array().unwrap() {
        let pt = m["plaintext"].as_str().unwrap().as_bytes();
        let ct = unhex(&m["ciphertext"]);
        assert_eq!(dev.seal(pt).unwrap(), ct);
        assert_eq!(&*phone.open(&ct).unwrap(), pt);
        msg::decode::<DeviceMsg>(pt).unwrap();
    }
}

#[test]
fn labels() {
    let all = vectors();
    let v = &all["label"];
    let device = KeyPair::from_scalar(&unhex(&all["session"]["device_private"])).unwrap();
    let label = Label::new(device.public_key());
    assert_eq!(
        label.url(v["base_url"].as_str().unwrap()),
        v["url"].as_str().unwrap()
    );
    assert_eq!(Label::parse_url(v["url"].as_str().unwrap()).unwrap(), label);
    assert_eq!(format_id(&label.id), v["display_id"].as_str().unwrap());
    for bad in all["invalid_labels"].as_array().unwrap() {
        let err = Label::parse_url(bad["url"].as_str().unwrap()).unwrap_err();
        assert_eq!(err.code(), bad["error"].as_str().unwrap(), "{bad}");
    }
}

#[test]
fn framing() {
    for f in vectors()["framing"].as_array().unwrap() {
        let msg = f["message"].as_str().unwrap().as_bytes();
        let max = f["max_chunk_len"].as_u64().unwrap() as usize;
        let expected: Vec<Vec<u8>> = f["chunks"].as_array().unwrap().iter().map(unhex).collect();
        assert_eq!(chunk(msg, max).unwrap(), expected);
        let mut r = Reassembler::new();
        let out: Vec<_> = expected.iter().filter_map(|c| r.push(c).unwrap()).collect();
        assert_eq!(out, vec![msg.to_vec()]);
    }
}

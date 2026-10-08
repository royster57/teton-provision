//! Session key agreement and sealing (SPEC.md §5).
//!
//! ```text
//! Z     = ECDH-P256(e, D) = ECDH-P256(d, E)
//! OKM   = HKDF-SHA256(ikm=Z, salt=N, info="teton-prov v1" ‖ id ‖ E ‖ D, L=64)
//! K_pd  = OKM[0..32]   phone → device
//! K_dp  = OKM[32..64]  device → phone
//! seal  = AES-256-GCM(K, iv = 0^4 ‖ u64_be(counter), aad = "")
//! ```

use aws_lc_rs::aead::{
    AES_256_GCM, Aad, LessSafeKey, NONCE_LEN as GCM_NONCE_LEN, Nonce, UnboundKey,
};
use aws_lc_rs::agreement::{self, ECDH_P256, ParsedPublicKey, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyBin, Pkcs8V1Der};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

/// Uncompressed SEC1 P-256 point: `0x04 ‖ x ‖ y`.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Per-connection device nonce (HKDF salt).
pub const NONCE_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
const INFO_LABEL: &[u8] = b"teton-prov v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid P-256 public key")]
    BadPublicKey,
    #[error("invalid private key")]
    BadPrivateKey,
    #[error("nonce must be {NONCE_LEN} bytes")]
    BadNonce,
    #[error("decryption failed")]
    Decrypt,
    #[error("message counter exhausted")]
    CounterExhausted,
    #[error("crypto backend failure")]
    Internal,
}

/// Checks that `bytes` is an uncompressed point on P-256.
pub fn validate_public_key(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() != PUBLIC_KEY_LEN || bytes[0] != 0x04 {
        return Err(CryptoError::BadPublicKey);
    }
    ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P256, bytes))
        .map(|_| ())
        .map_err(|_| CryptoError::BadPublicKey)
}

/// A P-256 ECDH key pair: the device's long-term key, or the phone's ephemeral one.
pub struct KeyPair {
    key: PrivateKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &crate::hex(&self.public))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        Self::wrap(PrivateKey::generate(&ECDH_P256).map_err(|_| CryptoError::Internal)?)
    }

    /// Loads a PKCS#8 (or RFC 5915) DER private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, CryptoError> {
        Self::wrap(
            PrivateKey::from_private_key_der(&ECDH_P256, der)
                .map_err(|_| CryptoError::BadPrivateKey)?,
        )
    }

    /// Loads a raw 32-byte big-endian scalar (test vectors).
    pub fn from_scalar(scalar: &[u8]) -> Result<Self, CryptoError> {
        Self::wrap(
            PrivateKey::from_private_key(&ECDH_P256, scalar)
                .map_err(|_| CryptoError::BadPrivateKey)?,
        )
    }

    fn wrap(key: PrivateKey) -> Result<Self, CryptoError> {
        let public_key = key
            .compute_public_key()
            .map_err(|_| CryptoError::Internal)?;
        let public = public_key
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::Internal)?;
        Ok(Self { key, public })
    }

    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let der: Pkcs8V1Der = self.key.as_der().map_err(|_| CryptoError::Internal)?;
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }

    pub fn scalar(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let bin: EcPrivateKeyBin = self.key.as_be_bytes().map_err(|_| CryptoError::Internal)?;
        Ok(Zeroizing::new(bin.as_ref().to_vec()))
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// Raw ECDH shared secret (the x-coordinate).
    pub fn agree(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        validate_public_key(peer_public)?;
        agreement::agree(
            &self.key,
            UnparsedPublicKey::new(&ECDH_P256, peer_public),
            CryptoError::BadPublicKey,
            |z| {
                let mut out = Zeroizing::new([0u8; KEY_LEN]);
                out.copy_from_slice(z);
                Ok(out)
            },
        )
    }
}

/// Directional session keys.
pub struct SessionKeys {
    pub phone_to_device: Zeroizing<[u8; KEY_LEN]>,
    pub device_to_phone: Zeroizing<[u8; KEY_LEN]>,
}

struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// The HKDF `info` input: `"teton-prov v1" ‖ id ‖ E ‖ D`.
pub fn hkdf_info(id: &str, ephemeral_public: &[u8], device_public: &[u8]) -> Vec<u8> {
    [INFO_LABEL, id.as_bytes(), ephemeral_public, device_public].concat()
}

pub fn derive_session_keys(
    shared_secret: &[u8],
    nonce: &[u8],
    id: &str,
    ephemeral_public: &[u8],
    device_public: &[u8],
) -> Result<SessionKeys, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce);
    }
    let info = [INFO_LABEL, id.as_bytes(), ephemeral_public, device_public];
    let mut okm = Zeroizing::new([0u8; 2 * KEY_LEN]);
    Salt::new(HKDF_SHA256, nonce)
        .extract(shared_secret)
        .expand(&info, OkmLen(2 * KEY_LEN))
        .and_then(|o: hkdf::Okm<'_, OkmLen>| o.fill(&mut okm[..]))
        .map_err(|_| CryptoError::Internal)?;
    let mut keys = SessionKeys {
        phone_to_device: Zeroizing::new([0; KEY_LEN]),
        device_to_phone: Zeroizing::new([0; KEY_LEN]),
    };
    keys.phone_to_device.copy_from_slice(&okm[..KEY_LEN]);
    keys.device_to_phone.copy_from_slice(&okm[KEY_LEN..]);
    Ok(keys)
}

/// Which end of the session we are; decides the send/receive keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Phone,
    Device,
}

struct Direction {
    key: LessSafeKey,
    counter: u64,
}

impl Direction {
    fn new(key: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::Internal)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            counter: 0,
        })
    }

    fn nonce(&self) -> Nonce {
        let mut iv = [0u8; GCM_NONCE_LEN];
        iv[4..].copy_from_slice(&self.counter.to_be_bytes());
        Nonce::assume_unique_for_key(iv)
    }

    fn advance(&mut self) -> Result<(), CryptoError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::CounterExhausted)?;
        Ok(())
    }
}

/// An established session: seals outgoing and opens incoming messages, each
/// direction with its own key and strictly sequential counter.
pub struct Channel {
    send: Direction,
    recv: Direction,
}

impl Channel {
    pub fn new(keys: &SessionKeys, role: Role) -> Result<Self, CryptoError> {
        let (send, recv) = match role {
            Role::Phone => (&keys.phone_to_device, &keys.device_to_phone),
            Role::Device => (&keys.device_to_phone, &keys.phone_to_device),
        };
        Ok(Self {
            send: Direction::new(send)?,
            recv: Direction::new(recv)?,
        })
    }

    /// Device side: derive the session from the phone's ephemeral public key.
    pub fn accept(
        device: &KeyPair,
        id: &str,
        nonce: &[u8],
        ephemeral_public: &[u8],
    ) -> Result<Self, CryptoError> {
        let z = device.agree(ephemeral_public)?;
        let keys = derive_session_keys(&*z, nonce, id, ephemeral_public, device.public_key())?;
        Self::new(&keys, Role::Device)
    }

    /// Phone side: derive the session from the device's label public key.
    pub fn initiate(
        ephemeral: &KeyPair,
        device_public: &[u8],
        id: &str,
        nonce: &[u8],
    ) -> Result<Self, CryptoError> {
        let z = ephemeral.agree(device_public)?;
        let keys = derive_session_keys(&*z, nonce, id, ephemeral.public_key(), device_public)?;
        Self::new(&keys, Role::Phone)
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = plaintext.to_vec();
        self.send
            .key
            .seal_in_place_append_tag(self.send.nonce(), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Internal)?;
        self.send.advance()?;
        Ok(buf)
    }

    /// Opens the next incoming message. The counter advances only on success,
    /// so a forged or replayed message cannot desynchronise the session.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = self
            .recv
            .key
            .open_in_place(self.recv.nonce(), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Decrypt)?
            .len();
        buf.truncate(len);
        self.recv.advance()?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; NONCE_LEN] = [7; NONCE_LEN];

    fn pair() -> (Channel, Channel) {
        let device = KeyPair::generate().unwrap();
        let eph = KeyPair::generate().unwrap();
        let phone = Channel::initiate(&eph, device.public_key(), "ID", &NONCE).unwrap();
        let dev = Channel::accept(&device, "ID", &NONCE, eph.public_key()).unwrap();
        (phone, dev)
    }

    #[test]
    fn both_directions() {
        let (mut phone, mut dev) = pair();
        for i in 0..3u8 {
            let ct = phone.seal(&[i; 5]).unwrap();
            assert_eq!(&*dev.open(&ct).unwrap(), &[i; 5]);
            let ct = dev.seal(&[i; 9]).unwrap();
            assert_eq!(&*phone.open(&ct).unwrap(), &[i; 9]);
        }
    }

    #[test]
    fn replay_and_reorder_rejected() {
        let (mut phone, mut dev) = pair();
        let first = phone.seal(b"one").unwrap();
        let second = phone.seal(b"two").unwrap();
        assert_eq!(dev.open(&second).err(), Some(CryptoError::Decrypt));
        dev.open(&first).unwrap();
        assert_eq!(dev.open(&first).err(), Some(CryptoError::Decrypt));
        dev.open(&second).unwrap();
    }

    #[test]
    fn reflection_rejected() {
        // A device message fed back to the device must not decrypt (directional keys).
        let (_, mut dev) = pair();
        let ct = dev.seal(b"ready").unwrap();
        assert_eq!(dev.open(&ct).err(), Some(CryptoError::Decrypt));
    }

    #[test]
    fn wrong_device_key_cannot_open() {
        let device = KeyPair::generate().unwrap();
        let impostor = KeyPair::generate().unwrap();
        let eph = KeyPair::generate().unwrap();
        let mut phone = Channel::initiate(&eph, device.public_key(), "ID", &NONCE).unwrap();
        let mut fake = Channel::accept(&impostor, "ID", &NONCE, eph.public_key()).unwrap();
        let ct = phone.seal(b"psk").unwrap();
        assert_eq!(fake.open(&ct).err(), Some(CryptoError::Decrypt));
    }

    #[test]
    fn session_bound_to_nonce_and_id() {
        let device = KeyPair::generate().unwrap();
        let eph = KeyPair::generate().unwrap();
        let mut phone = Channel::initiate(&eph, device.public_key(), "ID", &NONCE).unwrap();
        let ct = phone.seal(b"x").unwrap();
        let mut other_nonce = Channel::accept(&device, "ID", &[8; 16], eph.public_key()).unwrap();
        assert!(other_nonce.open(&ct).is_err());
        let mut other_id = Channel::accept(&device, "IE", &NONCE, eph.public_key()).unwrap();
        assert!(other_id.open(&ct).is_err());
    }

    #[test]
    fn pkcs8_round_trip() {
        let k = KeyPair::generate().unwrap();
        let k2 = KeyPair::from_pkcs8(&k.to_pkcs8().unwrap()).unwrap();
        assert_eq!(k.public_key(), k2.public_key());
        let k3 = KeyPair::from_scalar(&k.scalar().unwrap()).unwrap();
        assert_eq!(k.public_key(), k3.public_key());
    }

    #[test]
    fn rejects_invalid_public_keys() {
        let k = KeyPair::generate().unwrap();
        let mut off_curve = *k.public_key();
        off_curve[64] ^= 1;
        assert!(validate_public_key(&off_curve).is_err());
        assert!(validate_public_key(&k.public_key()[..33]).is_err());
        let mut compressed_tag = *k.public_key();
        compressed_tag[0] = 0x02;
        assert!(validate_public_key(&compressed_tag).is_err());
        assert!(k.agree(&off_curve).is_err());
        assert_eq!(
            derive_session_keys(&[0; 32], &[0; 15], "ID", &[], &[]).err(),
            Some(CryptoError::BadNonce)
        );
    }
}

//! Noise IK Handshake Protocol
//!
//! Implements the Noise IK pattern used by WireGuard for secure key exchange.
//!
//! ## Pattern: IK
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! - Initiator knows responder's static public key beforehand
//! - Provides mutual authentication and forward secrecy

use chacha20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    ChaCha20Poly1305,
};
use sha2::{Sha256, Digest};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret, EphemeralSecret};

use crate::crypto::{KeyPair, PublicKey};
use crate::error::{RiftError, Result};
use crate::noise::Session;

/// Protocol name for hashing
const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";

/// Empty payload for AEAD
const EMPTY: &[u8] = &[];

/// Handshake message type identifiers
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    /// Initiator's first message
    Init = 1,
    /// Responder's reply
    Response = 2,
}

/// Initiator's first handshake message
#[derive(Clone, Debug)]
pub struct HandshakeInit {
    /// Message type (1)
    pub msg_type: u8,
    /// Sender's index (for session identification)
    pub sender_index: u32,
    /// Ephemeral public key (32 bytes)
    pub ephemeral: [u8; 32],
    /// Encrypted static public key (32 + 16 = 48 bytes)
    pub encrypted_static: [u8; 48],
    /// Encrypted timestamp (12 + 16 = 28 bytes)
    pub encrypted_timestamp: [u8; 28],
    /// MAC1 for DoS protection
    pub mac1: [u8; 16],
}

impl HandshakeInit {
    pub const SIZE: usize = 1 + 4 + 32 + 48 + 28 + 16; // 129 bytes

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type;
        buf[1..5].copy_from_slice(&self.sender_index.to_le_bytes());
        buf[5..37].copy_from_slice(&self.ephemeral);
        buf[37..85].copy_from_slice(&self.encrypted_static);
        buf[85..113].copy_from_slice(&self.encrypted_timestamp);
        buf[113..129].copy_from_slice(&self.mac1);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(RiftError::Protocol("HandshakeInit too short".into()));
        }

        if buf[0] != HandshakeType::Init as u8 {
            return Err(RiftError::Protocol("Invalid handshake type".into()));
        }

        Ok(Self {
            msg_type: buf[0],
            sender_index: u32::from_le_bytes(buf[1..5].try_into().unwrap()),
            ephemeral: buf[5..37].try_into().unwrap(),
            encrypted_static: buf[37..85].try_into().unwrap(),
            encrypted_timestamp: buf[85..113].try_into().unwrap(),
            mac1: buf[113..129].try_into().unwrap(),
        })
    }
}

/// Responder's handshake response
#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    /// Message type (2)
    pub msg_type: u8,
    /// Sender's index
    pub sender_index: u32,
    /// Receiver's index (from init)
    pub receiver_index: u32,
    /// Ephemeral public key (32 bytes)
    pub ephemeral: [u8; 32],
    /// Encrypted empty (just auth tag = 16 bytes)
    pub encrypted_nothing: [u8; 16],
    /// MAC1 for DoS protection
    pub mac1: [u8; 16],
}

impl HandshakeResponse {
    pub const SIZE: usize = 1 + 4 + 4 + 32 + 16 + 16; // 73 bytes

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type;
        buf[1..5].copy_from_slice(&self.sender_index.to_le_bytes());
        buf[5..9].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[9..41].copy_from_slice(&self.ephemeral);
        buf[41..57].copy_from_slice(&self.encrypted_nothing);
        buf[57..73].copy_from_slice(&self.mac1);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(RiftError::Protocol("HandshakeResponse too short".into()));
        }

        if buf[0] != HandshakeType::Response as u8 {
            return Err(RiftError::Protocol("Invalid handshake type".into()));
        }

        Ok(Self {
            msg_type: buf[0],
            sender_index: u32::from_le_bytes(buf[1..5].try_into().unwrap()),
            receiver_index: u32::from_le_bytes(buf[5..9].try_into().unwrap()),
            ephemeral: buf[9..41].try_into().unwrap(),
            encrypted_nothing: buf[41..57].try_into().unwrap(),
            mac1: buf[57..73].try_into().unwrap(),
        })
    }
}

/// Symmetric state during handshake
struct SymmetricState {
    /// Chaining key for key derivation
    ck: [u8; 32],
    /// Hash of handshake transcript
    h: [u8; 32],
    /// Current encryption key (derived during handshake)
    k: Option<[u8; 32]>,
}

impl SymmetricState {
    fn new() -> Self {
        // Initialize with protocol name hash
        let h = Sha256::digest(PROTOCOL_NAME);
        Self {
            ck: h.into(),
            h: h.into(),
            k: None,
        }
    }

    /// Mix data into the hash
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// Mix key material using HKDF
    fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, k) = hkdf(&self.ck, input_key_material);
        self.ck = ck;
        self.k = Some(k);
    }

    /// Encrypt and authenticate data
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let k = self.k.ok_or_else(|| RiftError::Crypto("No key available".into()))?;
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&k));

        // Use zero nonce (we only encrypt once per key)
        let nonce = GenericArray::from_slice(&[0u8; 12]);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RiftError::Crypto(format!("Encryption failed: {}", e)))?;

        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt and verify data
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let k = self.k.ok_or_else(|| RiftError::Crypto("No key available".into()))?;
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&k));

        let nonce = GenericArray::from_slice(&[0u8; 12]);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| RiftError::Crypto(format!("Decryption failed: {}", e)))?;

        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Split into transport keys
    fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf(&self.ck, &[])
    }
}

/// HKDF-like key derivation (simplified for Noise)
fn hkdf(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HMAC-SHA256(ck, input)
    let temp = hmac_sha256(ck, input);

    // Output 1: HMAC-SHA256(temp, 0x01)
    let out1 = hmac_sha256(&temp, &[0x01]);

    // Output 2: HMAC-SHA256(temp, out1 || 0x02)
    let mut input2 = [0u8; 33];
    input2[..32].copy_from_slice(&out1);
    input2[32] = 0x02;
    let out2 = hmac_sha256(&temp, &input2);

    (out1, out2)
}

/// Simple HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Inner hash
    let mut ipad = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer hash
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        opad[i] ^= key_block[i];
    }

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

/// MAC for DoS protection
fn compute_mac1(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let hash = hmac_sha256(key, data);
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&hash[..16]);
    mac
}

/// Initiator side of the handshake
pub struct HandshakeInitiator {
    /// Our static keypair
    static_keypair: KeyPair,
    /// Our ephemeral secret
    ephemeral_secret: StaticSecret,
    /// Our ephemeral public
    ephemeral_public: X25519Public,
    /// Responder's static public key
    responder_static: PublicKey,
    /// Symmetric state
    state: SymmetricState,
    /// Our sender index
    sender_index: u32,
}

impl HandshakeInitiator {
    /// Create a new handshake initiator
    pub fn new(static_keypair: KeyPair, responder_static: PublicKey) -> Self {
        let mut rng = rand::thread_rng();

        // Generate ephemeral keypair
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Generate random sender index
        let sender_index = rng.next_u32();

        Self {
            static_keypair,
            ephemeral_secret,
            ephemeral_public,
            responder_static,
            state: SymmetricState::new(),
            sender_index,
        }
    }

    /// Generate the initial handshake message
    pub fn create_init(&mut self) -> Result<HandshakeInit> {
        // Mix in responder's static public key (pre-message pattern)
        self.state.mix_hash(&self.responder_static.wg_public_key());

        // e: Generate and send ephemeral
        let ephemeral = self.ephemeral_public.to_bytes();
        self.state.mix_hash(&ephemeral);

        // es: DH(ephemeral, responder_static)
        let responder_static_x25519 = X25519Public::from(self.responder_static.wg_public_key());
        let es = self.ephemeral_secret.diffie_hellman(&responder_static_x25519);
        self.state.mix_key(es.as_bytes());

        // s: Encrypt our static public key
        let our_static = self.static_keypair.public_key().wg_public_key();
        let encrypted_static_vec = self.state.encrypt_and_hash(&our_static)?;
        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&encrypted_static_vec);

        // ss: DH(our_static, responder_static)
        let ss = self.static_keypair.wg_private_key();
        let ss_secret = StaticSecret::from(ss);
        let ss_shared = ss_secret.diffie_hellman(&responder_static_x25519);
        self.state.mix_key(ss_shared.as_bytes());

        // Encrypt timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_le_bytes();
        let mut ts_padded = [0u8; 12];
        ts_padded[..8].copy_from_slice(&timestamp);
        let encrypted_timestamp_vec = self.state.encrypt_and_hash(&ts_padded)?;
        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp.copy_from_slice(&encrypted_timestamp_vec);

        // Compute MAC1
        let mac1_key = Sha256::digest(b"mac1----").into();
        let mut msg_for_mac = Vec::new();
        msg_for_mac.push(HandshakeType::Init as u8);
        msg_for_mac.extend_from_slice(&self.sender_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&ephemeral);
        msg_for_mac.extend_from_slice(&encrypted_static);
        msg_for_mac.extend_from_slice(&encrypted_timestamp);
        let mac1 = compute_mac1(&mac1_key, &msg_for_mac);

        Ok(HandshakeInit {
            msg_type: HandshakeType::Init as u8,
            sender_index: self.sender_index,
            ephemeral,
            encrypted_static,
            encrypted_timestamp,
            mac1,
        })
    }

    /// Process the response and derive session keys
    pub fn process_response(&mut self, response: &HandshakeResponse) -> Result<(Session, u32)> {
        // Verify receiver index matches
        if response.receiver_index != self.sender_index {
            return Err(RiftError::Protocol("Invalid receiver index".into()));
        }

        // e: Mix in responder's ephemeral
        self.state.mix_hash(&response.ephemeral);

        let responder_ephemeral = X25519Public::from(response.ephemeral);

        // ee: DH(our_ephemeral, responder_ephemeral)
        let ee = self.ephemeral_secret.diffie_hellman(&responder_ephemeral);
        self.state.mix_key(ee.as_bytes());

        // se: DH(our_static, responder_ephemeral)
        let our_static_secret = StaticSecret::from(self.static_keypair.wg_private_key());
        let se = our_static_secret.diffie_hellman(&responder_ephemeral);
        self.state.mix_key(se.as_bytes());

        // Decrypt empty (just verify)
        self.state.decrypt_and_hash(&response.encrypted_nothing)?;

        // Derive transport keys
        let (send_key, recv_key) = self.state.split();

        // Create session
        let session = Session::from_keys(
            send_key,
            recv_key,
            self.responder_static.clone(),
        );

        Ok((session, response.sender_index))
    }

    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }
}

/// Responder side of the handshake
pub struct HandshakeResponder {
    /// Our static keypair
    static_keypair: KeyPair,
    /// Our ephemeral secret (generated during process_init)
    ephemeral_secret: Option<StaticSecret>,
    /// Symmetric state
    state: SymmetricState,
    /// Initiator's static public key (learned from handshake)
    initiator_static: Option<PublicKey>,
    /// Initiator's sender index
    initiator_index: Option<u32>,
    /// Our sender index
    sender_index: u32,
}

impl HandshakeResponder {
    /// Create a new handshake responder
    pub fn new(static_keypair: KeyPair) -> Self {
        let mut rng = rand::thread_rng();

        Self {
            static_keypair,
            ephemeral_secret: None,
            state: SymmetricState::new(),
            initiator_static: None,
            initiator_index: None,
            sender_index: rng.next_u32(),
        }
    }

    /// Process an init message and generate response
    pub fn process_init(&mut self, init: &HandshakeInit) -> Result<HandshakeResponse> {
        // Mix in our static public key (pre-message pattern)
        self.state.mix_hash(&self.static_keypair.public_key().wg_public_key());

        // e: Mix in initiator's ephemeral
        self.state.mix_hash(&init.ephemeral);
        let initiator_ephemeral = X25519Public::from(init.ephemeral);

        // es: DH(our_static, initiator_ephemeral)
        let our_static_secret = StaticSecret::from(self.static_keypair.wg_private_key());
        let es = our_static_secret.diffie_hellman(&initiator_ephemeral);
        self.state.mix_key(es.as_bytes());

        // s: Decrypt initiator's static public key
        let initiator_static_bytes = self.state.decrypt_and_hash(&init.encrypted_static)?;
        let mut initiator_static_arr = [0u8; 32];
        initiator_static_arr.copy_from_slice(&initiator_static_bytes);

        // ss: DH(our_static, initiator_static)
        let initiator_static_x25519 = X25519Public::from(initiator_static_arr);
        let ss = our_static_secret.diffie_hellman(&initiator_static_x25519);
        self.state.mix_key(ss.as_bytes());

        // Decrypt and verify timestamp
        let timestamp_bytes = self.state.decrypt_and_hash(&init.encrypted_timestamp)?;
        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&timestamp_bytes[..8]);
        let timestamp = u64::from_le_bytes(ts_arr);

        // Verify timestamp is recent (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now.abs_diff(timestamp) > 300 {
            return Err(RiftError::Protocol("Timestamp too old".into()));
        }

        // Store initiator info
        self.initiator_static = Some(PublicKey::from_wg_key(initiator_static_arr)?);
        self.initiator_index = Some(init.sender_index);

        // Generate our ephemeral
        let mut rng = rand::thread_rng();
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);
        let ephemeral = ephemeral_public.to_bytes();

        // e: Send our ephemeral
        self.state.mix_hash(&ephemeral);

        // ee: DH(our_ephemeral, initiator_ephemeral)
        let ee = ephemeral_secret.diffie_hellman(&initiator_ephemeral);
        self.state.mix_key(ee.as_bytes());

        // se: DH(our_ephemeral, initiator_static)
        let se = ephemeral_secret.diffie_hellman(&initiator_static_x25519);
        self.state.mix_key(se.as_bytes());

        self.ephemeral_secret = Some(ephemeral_secret);

        // Encrypt empty (just for authentication)
        let encrypted_nothing_vec = self.state.encrypt_and_hash(&[])?;
        let mut encrypted_nothing = [0u8; 16];
        encrypted_nothing.copy_from_slice(&encrypted_nothing_vec);

        // Compute MAC1
        let mac1_key = Sha256::digest(b"mac1----").into();
        let mut msg_for_mac = Vec::new();
        msg_for_mac.push(HandshakeType::Response as u8);
        msg_for_mac.extend_from_slice(&self.sender_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&init.sender_index.to_le_bytes());
        msg_for_mac.extend_from_slice(&ephemeral);
        msg_for_mac.extend_from_slice(&encrypted_nothing);
        let mac1 = compute_mac1(&mac1_key, &msg_for_mac);

        Ok(HandshakeResponse {
            msg_type: HandshakeType::Response as u8,
            sender_index: self.sender_index,
            receiver_index: init.sender_index,
            ephemeral,
            encrypted_nothing,
            mac1,
        })
    }

    /// Finalize and get the session
    pub fn finalize(&self) -> Result<(Session, PublicKey, u32)> {
        let initiator_static = self.initiator_static.clone()
            .ok_or_else(|| RiftError::Protocol("Handshake not complete".into()))?;
        let initiator_index = self.initiator_index
            .ok_or_else(|| RiftError::Protocol("Handshake not complete".into()))?;

        // Derive transport keys (responder's view: swap send/recv)
        let (recv_key, send_key) = self.state.split();

        let session = Session::from_keys(
            send_key,
            recv_key,
            initiator_static.clone(),
        );

        Ok((session, initiator_static, initiator_index))
    }

    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        // Generate keypairs
        let initiator_keys = KeyPair::generate();
        let responder_keys = KeyPair::generate();

        // Initiator creates handshake
        let mut initiator = HandshakeInitiator::new(
            initiator_keys.clone(),
            responder_keys.public_key(),
        );
        let init_msg = initiator.create_init().unwrap();

        // Verify message format
        assert_eq!(init_msg.msg_type, HandshakeType::Init as u8);

        // Responder processes init
        let mut responder = HandshakeResponder::new(responder_keys);
        let response_msg = responder.process_init(&init_msg).unwrap();

        // Verify response format
        assert_eq!(response_msg.msg_type, HandshakeType::Response as u8);
        assert_eq!(response_msg.receiver_index, init_msg.sender_index);

        // Initiator processes response
        let (initiator_session, _responder_index) = initiator.process_response(&response_msg).unwrap();

        // Responder finalizes
        let (responder_session, learned_initiator_key, _init_idx) = responder.finalize().unwrap();

        // Verify we learned the correct X25519 key (the WireGuard key)
        // Note: Ed25519 keys won't match since from_wg_key creates a derived one
        assert_eq!(
            learned_initiator_key.wg_public_key(),
            initiator_keys.public_key().wg_public_key()
        );

        // Test that sessions can communicate
        let msg = b"Hello from initiator!";
        let encrypted = initiator_session.encrypt_packet(msg).unwrap();
        let decrypted = responder_session.decrypt_packet(&encrypted).unwrap();
        assert_eq!(msg.as_slice(), decrypted.as_slice());

        // And in reverse
        let msg2 = b"Hello from responder!";
        let encrypted2 = responder_session.encrypt_packet(msg2).unwrap();
        let decrypted2 = initiator_session.decrypt_packet(&encrypted2).unwrap();
        assert_eq!(msg2.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_message_serialization() {
        let init = HandshakeInit {
            msg_type: 1,
            sender_index: 12345,
            ephemeral: [1u8; 32],
            encrypted_static: [2u8; 48],
            encrypted_timestamp: [3u8; 28],
            mac1: [4u8; 16],
        };

        let bytes = init.to_bytes();
        let parsed = HandshakeInit::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.sender_index, 12345);
        assert_eq!(parsed.ephemeral, [1u8; 32]);
    }
}

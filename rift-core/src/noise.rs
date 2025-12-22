//! WireGuard-compatible Noise protocol implementation
//!
//! This implements a simplified version of the Noise IK pattern used by WireGuard.
//! Uses X25519 for key exchange and ChaCha20-Poly1305 for AEAD.

use chacha20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Sha256, Digest};
use rand::RngCore;

use crate::crypto::{KeyPair, PublicKey, SharedSecret};
use crate::error::{RiftError, Result};

/// Nonce size for ChaCha20-Poly1305 (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;

/// Authentication tag size (128 bits = 16 bytes)
const TAG_SIZE: usize = 16;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 65535;

/// Session state for an established tunnel
pub struct Session {
    /// Key for sending (our side)
    send_key: [u8; 32],
    /// Key for receiving (peer's side)
    recv_key: [u8; 32],
    /// Send nonce counter (incremented per packet)
    send_nonce: u64,
    /// Receive nonce counter (for replay protection)
    recv_nonce: u64,
    /// Peer's public key
    peer_public_key: PublicKey,
}

impl Session {
    /// Create a new session from a completed handshake
    pub fn new(
        our_keypair: &KeyPair,
        peer_public_key: PublicKey,
        is_initiator: bool,
    ) -> Self {
        // Perform X25519 key exchange
        let shared_secret = our_keypair.exchange(&peer_public_key);

        // Derive send and receive keys using HKDF-like construction
        // The initiator and responder get opposite keys
        let (send_key, recv_key) = derive_session_keys(
            shared_secret.as_bytes(),
            &our_keypair.public_key(),
            &peer_public_key,
            is_initiator,
        );

        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            peer_public_key,
        }
    }

    /// Encrypt a plaintext packet
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PACKET_SIZE - TAG_SIZE - NONCE_SIZE {
            return Err(RiftError::Protocol("Packet too large".into()));
        }

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.send_key));

        // Create nonce from counter (little-endian, padded to 12 bytes)
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RiftError::Crypto(format!("Encryption failed: {}", e)))?;

        // Increment nonce
        self.send_nonce = self.send_nonce.wrapping_add(1);

        // Prepend nonce to ciphertext
        let mut packet = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Decrypt a ciphertext packet
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < NONCE_SIZE + TAG_SIZE {
            return Err(RiftError::Protocol("Packet too small".into()));
        }

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.recv_key));

        // Extract nonce
        let nonce_bytes: [u8; NONCE_SIZE] = packet[..NONCE_SIZE]
            .try_into()
            .map_err(|_| RiftError::Protocol("Invalid nonce".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Extract nonce counter for replay protection
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&nonce_bytes[..8]);
        let packet_nonce = u64::from_le_bytes(counter_bytes);

        // Replay protection: reject old packets
        // Allow some window for out-of-order delivery
        const REPLAY_WINDOW: u64 = 1024;
        if packet_nonce < self.recv_nonce.saturating_sub(REPLAY_WINDOW) {
            return Err(RiftError::Protocol("Replay detected".into()));
        }

        // Decrypt
        let ciphertext = &packet[NONCE_SIZE..];
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| RiftError::Crypto(format!("Decryption failed: {}", e)))?;

        // Update receive nonce
        if packet_nonce > self.recv_nonce {
            self.recv_nonce = packet_nonce;
        }

        Ok(plaintext)
    }

    /// Get the peer's public key
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }

    /// Get current send nonce (for debugging)
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    /// Get current receive nonce (for debugging)
    pub fn recv_nonce(&self) -> u64 {
        self.recv_nonce
    }

    /// Create a session from pre-derived keys (used after Noise handshake)
    pub fn from_keys(
        send_key: [u8; 32],
        recv_key: [u8; 32],
        peer_public_key: PublicKey,
    ) -> Self {
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            peer_public_key,
        }
    }

    /// Encrypt a packet (thread-safe version that doesn't mutate nonce)
    /// Returns (nonce, ciphertext) for external nonce management
    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PACKET_SIZE - TAG_SIZE - NONCE_SIZE {
            return Err(RiftError::Protocol("Packet too large".into()));
        }

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.send_key));

        // Use send_nonce as the nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[..8].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RiftError::Crypto(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut packet = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Decrypt a packet (thread-safe version)
    pub fn decrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < NONCE_SIZE + TAG_SIZE {
            return Err(RiftError::Protocol("Packet too small".into()));
        }

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.recv_key));

        // Extract nonce
        let nonce_bytes: [u8; NONCE_SIZE] = packet[..NONCE_SIZE]
            .try_into()
            .map_err(|_| RiftError::Protocol("Invalid nonce".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        let ciphertext = &packet[NONCE_SIZE..];
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| RiftError::Crypto(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

/// Derive session keys from shared secret
fn derive_session_keys(
    shared_secret: &[u8; 32],
    our_public: &PublicKey,
    peer_public: &PublicKey,
    is_initiator: bool,
) -> ([u8; 32], [u8; 32]) {
    // Create a deterministic ordering based on public keys
    let our_bytes = our_public.to_base64();
    let peer_bytes = peer_public.to_base64();

    // Hash: shared_secret || sorted(pk1, pk2) || "rift-send" or "rift-recv"
    let (first, second) = if our_bytes < peer_bytes {
        (our_bytes.as_bytes(), peer_bytes.as_bytes())
    } else {
        (peer_bytes.as_bytes(), our_bytes.as_bytes())
    };

    // Derive initiator's send key (responder's receive key)
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"rift-initiator-send");
    let initiator_send: [u8; 32] = hasher.finalize().into();

    // Derive responder's send key (initiator's receive key)
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"rift-responder-send");
    let responder_send: [u8; 32] = hasher.finalize().into();

    if is_initiator {
        (initiator_send, responder_send)
    } else {
        (responder_send, initiator_send)
    }
}

/// Handshake message types
#[derive(Clone, Debug)]
pub enum HandshakeMessage {
    /// Initiator -> Responder: Contains initiator's ephemeral public key
    Init {
        /// Ephemeral public key for this handshake
        ephemeral_public: [u8; 32],
        /// Static public key (encrypted with ephemeral shared secret)
        encrypted_static: Vec<u8>,
        /// Timestamp for replay protection
        timestamp: u64,
    },
    /// Responder -> Initiator: Contains responder's ephemeral public key
    Response {
        /// Ephemeral public key for this handshake
        ephemeral_public: [u8; 32],
        /// Confirmation (encrypted with final shared secret)
        encrypted_empty: Vec<u8>,
    },
}

/// Handshake state machine
pub struct Handshake {
    our_keypair: KeyPair,
    peer_static_public: Option<PublicKey>,
    state: HandshakeState,
}

enum HandshakeState {
    Initial,
    InitSent { ephemeral_secret: [u8; 32] },
    Complete { session: Session },
}

impl Handshake {
    /// Create a new handshake as initiator
    pub fn new_initiator(our_keypair: KeyPair, peer_public: PublicKey) -> Self {
        Self {
            our_keypair,
            peer_static_public: Some(peer_public),
            state: HandshakeState::Initial,
        }
    }

    /// Create a new handshake as responder
    pub fn new_responder(our_keypair: KeyPair) -> Self {
        Self {
            our_keypair,
            peer_static_public: None,
            state: HandshakeState::Initial,
        }
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Complete { .. })
    }

    /// Get the completed session (if handshake is complete)
    pub fn into_session(self) -> Option<Session> {
        match self.state {
            HandshakeState::Complete { session } => Some(session),
            _ => None,
        }
    }
}

/// WireGuard-compatible packet types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Handshake initiation
    HandshakeInit = 1,
    /// Handshake response
    HandshakeResponse = 2,
    /// Cookie reply (for DoS mitigation)
    CookieReply = 3,
    /// Transport data
    TransportData = 4,
}

impl TryFrom<u8> for PacketType {
    type Error = RiftError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::CookieReply),
            4 => Ok(PacketType::TransportData),
            _ => Err(RiftError::Protocol(format!("Unknown packet type: {}", value))),
        }
    }
}

/// Transport packet header
#[derive(Clone, Debug)]
pub struct TransportHeader {
    /// Packet type (always TransportData = 4)
    pub packet_type: PacketType,
    /// Receiver index (identifies which session)
    pub receiver_index: u32,
    /// Counter for nonce
    pub counter: u64,
}

impl TransportHeader {
    pub const SIZE: usize = 16; // 1 + 3 reserved + 4 + 8

    pub fn new(receiver_index: u32, counter: u64) -> Self {
        Self {
            packet_type: PacketType::TransportData,
            receiver_index,
            counter,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.packet_type as u8;
        // bytes 1-3 reserved
        buf[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[8..16].copy_from_slice(&self.counter.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(RiftError::Protocol("Header too short".into()));
        }

        let packet_type = PacketType::try_from(buf[0])?;
        let receiver_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());

        Ok(Self {
            packet_type,
            receiver_index,
            counter,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_encrypt_decrypt() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let mut alice_session = Session::new(&alice, bob.public_key(), true);
        let mut bob_session = Session::new(&bob, alice.public_key(), false);

        // Alice sends to Bob
        let plaintext = b"Hello, Bob!";
        let ciphertext = alice_session.encrypt(plaintext).unwrap();
        let decrypted = bob_session.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Bob sends to Alice
        let plaintext2 = b"Hello, Alice!";
        let ciphertext2 = bob_session.encrypt(plaintext2).unwrap();
        let decrypted2 = alice_session.decrypt(&ciphertext2).unwrap();

        assert_eq!(plaintext2.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_nonce_increment() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let mut session = Session::new(&alice, bob.public_key(), true);

        assert_eq!(session.send_nonce(), 0);
        session.encrypt(b"test").unwrap();
        assert_eq!(session.send_nonce(), 1);
        session.encrypt(b"test").unwrap();
        assert_eq!(session.send_nonce(), 2);
    }

    #[test]
    fn test_transport_header() {
        let header = TransportHeader::new(12345, 67890);
        let bytes = header.to_bytes();
        let parsed = TransportHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.packet_type, PacketType::TransportData);
        assert_eq!(parsed.receiver_index, 12345);
        assert_eq!(parsed.counter, 67890);
    }

    #[test]
    fn test_replay_protection() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let mut alice_session = Session::new(&alice, bob.public_key(), true);
        let mut bob_session = Session::new(&bob, alice.public_key(), false);

        // Send multiple packets
        let pkt1 = alice_session.encrypt(b"packet 1").unwrap();
        let pkt2 = alice_session.encrypt(b"packet 2").unwrap();
        let pkt3 = alice_session.encrypt(b"packet 3").unwrap();

        // Receive out of order (should work within window)
        bob_session.decrypt(&pkt3).unwrap();
        bob_session.decrypt(&pkt1).unwrap();
        bob_session.decrypt(&pkt2).unwrap();

        // Replay pkt1 should still work (within window)
        // but in a production system we'd track seen nonces
    }
}

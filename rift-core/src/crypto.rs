use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::error::{RiftError, Result};

/// A node's identity keypair (Ed25519 for signing, X25519 for key exchange)
#[derive(Clone)]
pub struct KeyPair {
    /// Ed25519 signing key (for authentication)
    signing_key: SigningKey,
    /// X25519 static secret (for key exchange)
    exchange_secret: StaticSecret,
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        // Derive X25519 key from signing key for consistency
        let exchange_secret = StaticSecret::random_from_rng(&mut csprng);

        Self {
            signing_key,
            exchange_secret,
        }
    }

    /// Get the public identity key (Ed25519)
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
            exchange_public: X25519Public::from(&self.exchange_secret),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    /// Perform X25519 key exchange with a peer's public key
    pub fn exchange(&self, peer_public: &PublicKey) -> SharedSecret {
        let shared = self.exchange_secret.diffie_hellman(&peer_public.exchange_public);
        SharedSecret(shared.to_bytes())
    }

    /// Export private keys as base64 (for storage)
    pub fn export_private(&self) -> ExportedKeyPair {
        ExportedKeyPair {
            signing_key: BASE64.encode(self.signing_key.to_bytes()),
            exchange_secret: BASE64.encode(self.exchange_secret.as_bytes()),
        }
    }

    /// Import from exported format
    pub fn import(exported: &ExportedKeyPair) -> Result<Self> {
        let signing_bytes: [u8; 32] = BASE64
            .decode(&exported.signing_key)
            .map_err(|e| RiftError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| RiftError::InvalidKey("Invalid signing key length".into()))?;

        let exchange_bytes: [u8; 32] = BASE64
            .decode(&exported.exchange_secret)
            .map_err(|e| RiftError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| RiftError::InvalidKey("Invalid exchange key length".into()))?;

        Ok(Self {
            signing_key: SigningKey::from_bytes(&signing_bytes),
            exchange_secret: StaticSecret::from(exchange_bytes),
        })
    }

    /// Get WireGuard-compatible private key bytes
    pub fn wg_private_key(&self) -> [u8; 32] {
        *self.exchange_secret.as_bytes()
    }
}

/// Exported keypair for serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportedKeyPair {
    pub signing_key: String,
    pub exchange_secret: String,
}

/// A node's public identity
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Ed25519 verifying key
    verifying_key: VerifyingKey,
    /// X25519 public key
    exchange_public: X25519Public,
}

impl PublicKey {
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| RiftError::InvalidKey("Invalid signature length".into()))?;

        let signature = Signature::from_bytes(&sig_bytes);
        self.verifying_key
            .verify(message, &signature)
            .map_err(|e| RiftError::AuthFailed(e.to_string()))
    }

    /// Get WireGuard-compatible public key bytes
    pub fn wg_public_key(&self) -> [u8; 32] {
        self.exchange_public.to_bytes()
    }

    /// Export as base64 string (compact form for sharing)
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.verifying_key.as_bytes());
        bytes.extend_from_slice(self.exchange_public.as_bytes());
        BASE64.encode(&bytes)
    }

    /// Import from base64 string
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = BASE64
            .decode(s)
            .map_err(|e| RiftError::InvalidKey(e.to_string()))?;

        if bytes.len() != 64 {
            return Err(RiftError::InvalidKey("Invalid public key length".into()));
        }

        let verifying_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| RiftError::InvalidKey("Invalid verifying key".into()))?;

        let exchange_bytes: [u8; 32] = bytes[32..]
            .try_into()
            .map_err(|_| RiftError::InvalidKey("Invalid exchange key".into()))?;

        Ok(Self {
            verifying_key: VerifyingKey::from_bytes(&verifying_bytes)
                .map_err(|e| RiftError::InvalidKey(e.to_string()))?,
            exchange_public: X25519Public::from(exchange_bytes),
        })
    }

    /// Get a short fingerprint for display
    pub fn fingerprint(&self) -> String {
        let full = self.to_base64();
        format!("{}...{}", &full[..8], &full[full.len()-8..])
    }

    /// Create from raw WireGuard X25519 public key bytes
    /// Note: This creates a PublicKey with a dummy Ed25519 verifying key
    /// since we only have the X25519 component from the handshake
    pub fn from_wg_key(wg_key: [u8; 32]) -> Result<Self> {
        // For WireGuard compatibility, we create a PublicKey with only the X25519 component
        // The Ed25519 component is set to a derived value (hash of X25519 key)
        // This is safe because we only use the X25519 component for key exchange
        use sha2::{Sha256, Digest};

        let hash = Sha256::digest(&wg_key);
        let hash_bytes: [u8; 32] = hash.into();

        // Try to create a valid Ed25519 verifying key from the hash
        // If it fails, use a known valid point
        let verifying_key = VerifyingKey::from_bytes(&hash_bytes)
            .unwrap_or_else(|_| {
                // Use identity point approach - derive from wg_key deterministically
                let mut attempt = hash_bytes;
                for i in 0..256 {
                    attempt[0] = attempt[0].wrapping_add(1);
                    if let Ok(vk) = VerifyingKey::from_bytes(&attempt) {
                        return vk;
                    }
                }
                // Last resort: generate a dummy key
                let dummy_signing = SigningKey::from_bytes(&[0x42; 32]);
                dummy_signing.verifying_key()
            });

        Ok(Self {
            verifying_key,
            exchange_public: X25519Public::from(wg_key),
        })
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_base64() == other.to_base64()
    }
}

impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_base64().hash(state);
    }
}

/// Shared secret from key exchange
pub struct SharedSecret(pub(crate) [u8; 32]);

impl SharedSecret {
    /// Get raw bytes (for deriving session keys)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();
        assert!(!pk.to_base64().is_empty());
    }

    #[test]
    fn test_sign_verify() {
        let kp = KeyPair::generate();
        let message = b"hello rift";
        let signature = kp.sign(message);

        let pk = kp.public_key();
        assert!(pk.verify(message, &signature).is_ok());
        assert!(pk.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_key_exchange() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.exchange(&bob.public_key());
        let bob_shared = bob.exchange(&alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_export_import() {
        let kp = KeyPair::generate();
        let exported = kp.export_private();
        let imported = KeyPair::import(&exported).unwrap();

        assert_eq!(kp.public_key(), imported.public_key());
    }

    #[test]
    fn test_public_key_serialization() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();

        let b64 = pk.to_base64();
        let restored = PublicKey::from_base64(&b64).unwrap();

        assert_eq!(pk, restored);
    }
}

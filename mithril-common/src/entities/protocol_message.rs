use std::{collections::BTreeMap, fmt::Display, hash::Hash};

use sha2::{Digest, Sha256};
use strum_macros::EnumDiscriminants;

use crate::crypto_helper::ProtocolAggregateVerificationKey;

/// The key of a ProtocolMessage
#[derive(Debug, Clone, EnumDiscriminants)]
#[strum_discriminants(name(ProtocolMessagePartKey), derive(Hash, Ord, PartialOrd))]
pub enum ProtocolMessagePart {
    /// The ProtocolMessage part key associated to the Snapshot Digest
    SnapshotDigest(String),

    /// The ProtocolMessage part key associated to the Next epoch aggregate verification key
    /// The AVK that will be allowed to be used to sign during the next epoch
    /// aka AVK(n-1)
    NextAggregateVerificationKey(ProtocolAggregateVerificationKey),
}

impl Display for ProtocolMessagePartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SnapshotDigest => write!(f, "snapshot_digest"),
            Self::NextAggregateVerificationKey => write!(f, "next_aggregate_verification_key"),
        }
    }
}

/// ProtocolMessage represents a message that is signed (or verified) by the Mithril protocol
#[derive(Clone, Debug, Default)]
pub struct ProtocolMessage {
    /// Map of the messages combined into the digest
    /// aka MSG(p,n)
    pub message_parts: BTreeMap<ProtocolMessagePartKey, ProtocolMessagePart>,
    // todo: should this type be more like this ?
    //aggregate_verification_key: Option<ProtocolAggregateVerificationKey>,
}

impl ProtocolMessage {
    /// ProtocolMessage factory
    pub fn new() -> ProtocolMessage {
        ProtocolMessage {
            message_parts: BTreeMap::new(),
        }
    }

    /// Set the message part associated with a key
    /// Returns previously set value if it exists
    pub fn set_message_part(&mut self, value: ProtocolMessagePart) {
        let key: ProtocolMessagePartKey = value.clone().into(); // todo: can we avoid cloning the whole object ?
        self.message_parts.insert(key, value);
    }

    /// Get the message part associated with a key
    pub fn get_message_part(&self, key: &ProtocolMessagePartKey) -> Option<&ProtocolMessagePart> {
        self.message_parts.get(key)
    }

    /// Get the aggregate verification key of this message if any
    pub fn get_aggregate_verification_key(&self) -> Option<&ProtocolAggregateVerificationKey> {
        match self.get_message_part(&ProtocolMessagePartKey::NextAggregateVerificationKey) {
            Some(a_thing) => match a_thing {
                ProtocolMessagePart::SnapshotDigest(_) => {
                    panic!("A SnapshotDigest was assigned as the NextAggregateVerificationKey")
                }
                ProtocolMessagePart::NextAggregateVerificationKey(avk) => Some(avk),
            },
            None => None,
        }
    }

    /// Get the snapshot digest verification key of this message if any
    pub fn get_snapshot_digest(&self) -> Option<&str> {
        match self.get_message_part(&ProtocolMessagePartKey::SnapshotDigest) {
            Some(a_thing) => match a_thing {
                ProtocolMessagePart::SnapshotDigest(digest) => Some(digest),
                ProtocolMessagePart::NextAggregateVerificationKey(_) => {
                    panic!("A NextAggregateVerificationKey was assigned as the SnapshotDigest")
                }
            },
            None => None,
        }
    }

    /// Computes the hash of the protocol message
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        self.message_parts.iter().for_each(|(k, v)| {
            hasher.update(k.to_string().as_bytes());
            match v {
                ProtocolMessagePart::SnapshotDigest(digest) => hasher.update(digest.as_bytes()),
                ProtocolMessagePart::NextAggregateVerificationKey(avk) => {
                    hasher.update(avk.to_json_hex().unwrap().as_bytes())
                }
            };
        });
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::fake_keys;

    use super::*;

    #[test]
    fn test_protocol_message_compute_hash() {
        let hash_expected = "07f1938b6f1ef9a3bb4b9b12f66866e96a4e918c1e6b22e9720e0c895a925d01";

        let mut protocol_message = ProtocolMessage::new();
        protocol_message.set_message_part(ProtocolMessagePart::SnapshotDigest(
            "snapshot-digest-123".to_string(),
        ));
        protocol_message.set_message_part(ProtocolMessagePart::NextAggregateVerificationKey(
            fake_keys::aggregate_verification_key()[0]
                .try_into()
                .unwrap(),
        ));
        assert_eq!(hash_expected, protocol_message.compute_hash());

        let mut protocol_message_modified = protocol_message.clone();
        protocol_message_modified.set_message_part(
            ProtocolMessagePart::NextAggregateVerificationKey(
                fake_keys::aggregate_verification_key()[1]
                    .try_into()
                    .unwrap(),
            ),
        );
        assert_ne!(hash_expected, protocol_message_modified.compute_hash());

        let mut protocol_message_modified = protocol_message.clone();
        protocol_message_modified.set_message_part(ProtocolMessagePart::SnapshotDigest(
            "snapshot-digest-456".to_string(),
        ));
        assert_ne!(hash_expected, protocol_message_modified.compute_hash());
    }
}

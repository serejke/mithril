use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Display};

/// The key of a ProtocolMessage
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolMessagePartKey {
    /// The ProtocolMessage part key associated to the Snapshot Digest
    #[serde(rename = "snapshot_digest")]
    SnapshotDigest,

    /// The ProtocolMessage part key associated to the Next epoch aggregate verification key
    /// The AVK that will be allowed to be used to sign during the next epoch
    /// aka AVK(n-1)
    #[serde(rename = "next_aggregate_verification_key")]
    NextAggregateVerificationKey,
}

impl Display for ProtocolMessagePartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SnapshotDigest => write!(f, "snapshot_digest"),
            Self::NextAggregateVerificationKey => write!(f, "next_aggregate_verification_key"),
        }
    }
}

/// The value of a ProtocolMessage
pub type ProtocolMessagePartValue = String;

/// ProtocolMessage represents a message that is signed (or verified) by the Mithril protocol
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Map of the messages combined into the digest
    /// aka MSG(p,n)
    pub message_parts: BTreeMap<ProtocolMessagePartKey, ProtocolMessagePartValue>,
}

impl ProtocolMessage {
    /// ProtocolMessage factory
    pub fn new(
        values: BTreeMap<ProtocolMessagePartKey, ProtocolMessagePartValue>,
    ) -> ProtocolMessage {
        ProtocolMessage {
            message_parts: values,
        }
    }
}

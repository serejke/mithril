use blake2::{digest::typenum::U32, Blake2b};
use hex::FromHex;
use mithril_stm::stm::StmParameters;
use mithril_stm::stm::{StmAggrSig, StmAggrVerificationKey};
use serde::Deserialize;
use std::convert::{TryFrom, TryInto};
use wasm_bindgen::JsValue;

use super::{fetch_certificate, fetch_genesis_verification_key, key_decode_hex, print_window};

pub(crate) type D = Blake2b<U32>;

#[derive(Debug)]
pub enum CertificateSignature {
    MultiSignature(StmAggrSig<D>),
    GenesisSignature(ed25519_dalek::Signature),
}

impl CertificateSignature {
    pub fn verify(
        &self,
        message: &[u8],
        avk: &StmAggrVerificationKey<D>,
        protocol_parameters: &StmParameters,
        genesis_verification_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), String> {
        match self {
            Self::GenesisSignature(signature) => genesis_verification_key
                .verify_strict(message, signature)
                .map_err(|e| format!("ERROR GENESIS={e}")),
            Self::MultiSignature(signature) => signature
                .verify(message, avk, protocol_parameters)
                .map_err(|e| format!("ERROR MULTISIG={e}")),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CertificateMetadata {
    pub parameters: StmParameters,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CertificateBeacon {
    pub network: String,
    pub epoch: u64,
}

#[derive(Debug, Deserialize)]
pub struct CertificateMessage {
    hash: String,
    previous_hash: String,
    multi_signature: String,
    genesis_signature: String,
    aggregate_verification_key: String,
    signed_message: String,
    beacon: CertificateBeacon,
    metadata: CertificateMetadata,
}

#[derive(Debug)]
pub struct Certificate {
    pub hash: String,
    pub previous_hash: Option<String>,
    pub epoch: u64,
    pub signature: CertificateSignature,
    pub avk: StmAggrVerificationKey<D>,
    pub message: Vec<u8>,
    pub protocol_parameters: StmParameters,
}

impl TryFrom<CertificateMessage> for Certificate {
    type Error = String;

    fn try_from(value: CertificateMessage) -> Result<Certificate, Self::Error> {
        let signature = if value.previous_hash.is_empty() {
            &value.genesis_signature
        } else {
            &value.multi_signature
        };

        Certificate::new(
            &value.hash,
            &value.previous_hash,
            &value.beacon.epoch,
            signature,
            &value.aggregate_verification_key,
            &value.signed_message,
            &value.metadata.parameters,
        )
    }
}

impl Certificate {
    pub fn new(
        hash: &str,
        previous_hash: &str,
        epoch: &u64,
        signature: &str,
        avk: &str,
        message: &str,
        protocol_parameters: &StmParameters,
    ) -> Result<Self, String> {
        let previous_hash = if previous_hash.is_empty() {
            None
        } else {
            Some(previous_hash.to_owned())
        };
        let signature = if previous_hash.is_some() {
            CertificateSignature::MultiSignature(key_decode_hex(signature)?)
        } else {
            let signature = ed25519_dalek::Signature::from_bytes(
                Vec::from_hex(signature)
                    .map_err(|e| format!("HEX parsing error: {e}"))?
                    .as_slice()
                    .try_into()
                    .map_err(|e| {
                        format!("The given signature is not 64 bytes long. ERROR = '{e}'.")
                    })?,
            );
            CertificateSignature::GenesisSignature(signature)
        };

        let myself = Self {
            hash: hash.to_owned(),
            previous_hash,
            epoch: epoch.to_owned(),
            signature,
            avk: key_decode_hex(avk)?,
            message: message.as_bytes().to_owned(),
            protocol_parameters: protocol_parameters.to_owned(),
        };

        Ok(myself)
    }

    pub fn is_genesis(&self) -> bool {
        self.previous_hash.is_none()
    }

    // In this PoC, the certificate is considered valid if the signature is valid (multi-signature or genesis signature).
    // In particular, the hash of the certificate is not verified.
    pub fn verify(
        &self,
        genesis_verification_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), String> {
        self.signature
            .verify(
                &self.message,
                &self.avk,
                &self.protocol_parameters,
                genesis_verification_key,
            )
            .map_err(|e| format!("ERROR: {e:?}"))
    }
}

// In this PoC, the certificate chain is considered valid if each of its certificate is valid
// We don't test if the AVK of the next epoch is signed in the master certificate of the previous epoch.
pub async fn verify_certificate_chain(
    aggregator_endpoint: &str,
    certificate_hash: &str,
    genesis_verification_key_url: &str,
) -> Result<Certificate, JsValue> {
    print_window("<h3>Verifying the certificate chain:</h3>").unwrap();

    let genesis_verification_key =
        fetch_genesis_verification_key(genesis_verification_key_url).await?;

    let mut certificate = fetch_certificate(aggregator_endpoint, certificate_hash).await?;
    loop {
        certificate.verify(&genesis_verification_key).map_err(|e| {
            format!(
                "Verification failed for certificate hash='{}', ERROR = '{e}",
                certificate.hash
            )
        })?;
        let certificate_hash = &certificate.hash;
        let certificate_type = if certificate.is_genesis() {
            "Genesis"
        } else {
            "Mithril"
        };
        let certificate_epoch = certificate.epoch;
        print_window(&format!(
            ">> ✔️ {certificate_type} certificate <a href='{aggregator_endpoint}/certificate/{certificate_hash}' target='_blank'>#<b>{certificate_hash}</b></a> at epoch <b>#{certificate_epoch}</b> is valid.",
        ))
        .unwrap();

        certificate = match &certificate.previous_hash {
            None => break,
            Some(hash) => fetch_certificate(aggregator_endpoint, hash).await?,
        }
    }

    Ok(certificate)
}

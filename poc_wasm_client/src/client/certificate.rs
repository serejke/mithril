use blake2::{digest::typenum::U32, Blake2b};
use hex::FromHex;
use mithril_stm::stm::StmParameters;
use mithril_stm::stm::{StmAggrSig, StmAggrVerificationKey};
use serde::Deserialize;
use std::convert::{TryFrom, TryInto};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use super::key_decode_hex;

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

#[derive(Debug, Deserialize)]
pub struct CertificateMessage {
    hash: String,
    previous_hash: String,
    multi_signature: String,
    genesis_signature: String,
    aggregate_verification_key: String,
    signed_message: String,
    metadata: CertificateMetadata,
}

#[derive(Debug)]
pub struct Certificate {
    pub hash: String,
    pub previous_hash: Option<String>,
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
            signature,
            avk: key_decode_hex(avk)?,
            message: message.as_bytes().to_owned(),
            protocol_parameters: protocol_parameters.to_owned(),
        };

        Ok(myself)
    }

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

pub async fn fetch_certificate(
    aggregator_endpoint: &str,
    hash: &str,
) -> Result<Certificate, String> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);
    let url = format!("{aggregator_endpoint}/certificate/{hash}");
    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("WEB-SYS: request error: {e:?}"))?;
    request
        .headers()
        .set("Accept", "application/vnd.github.v3+json")
        .map_err(|e| format!("WEB-SYS: headers error: {e:?}"))?;
    let window = web_sys::window().ok_or_else(|| "WEB-SYS: no Window created!".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("WEB-SYS: fetch error: {e:?}"))?;
    let response: Response = resp_value
        .dyn_into()
        .map_err(|e| format!("WEB-SYS: response error: {e:?}"))?;
    let js_value = JsFuture::from(
        response
            .text()
            .map_err(|e| format!("WEB-SYS: Cannot read JSON response from body: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("WEB-SYS: Cannot read JS memory: {e:?}"))?;
    let certificate_message: CertificateMessage = serde_json::from_str(
        &js_value
            .as_string()
            .ok_or_else(|| "WEB-SYS: given JSON is not a String".to_string())?,
    )
    .map_err(|_| {
        "SERDE-JSON: Could not deserialize CertificateMessge from given JSON ".to_string()
    })?;

    certificate_message.try_into()
}

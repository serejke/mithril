mod client;

use wasm_bindgen::prelude::*;

use client::*;

pub const GENESIS_VERIFICATION_KEY: &str = "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d";
pub const AGGREGATOR_ENDPOINT: &str =
    "https://aggregator.release-preprod.api.mithril.network/aggregator";

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

#[wasm_bindgen(start)]
pub async fn main() -> Result<(), JsValue> {
    let certificate_hash = "61b241a842ae986e54df26a43f5ebef2c6876d1b6fba5122cb20ca77df74131f";
    let aggregator_endpoint = AGGREGATOR_ENDPOINT;
    let genesis_verification_key = GENESIS_VERIFICATION_KEY;

    let chain_verification = verify_certificate_chain(
        aggregator_endpoint,
        certificate_hash,
        genesis_verification_key,
    )
    .await;
    match &chain_verification {
        Ok(_) => {
            alert("✅ certificate chain verified!");
        }
        Err(e) => {
            alert(&format!("❌ certificate chain invalid: {:?}", e));
        }
    }
    chain_verification?;

    Ok(())
}

pub async fn verify_certificate_chain(
    aggregator_endpoint: &str,
    certificate_hash: &str,
    genesis_verification_key: &str,
) -> Result<Certificate, JsValue> {
    let genesis_verification_key: ed25519_dalek::VerifyingKey =
        key_decode_hex(genesis_verification_key)?;

    let mut certificate = fetch_certificate(aggregator_endpoint, certificate_hash).await?;

    loop {
        certificate.verify(&genesis_verification_key).map_err(|e| {
            format!(
                "Verification failed for certificate hash='{}', ERROR = '{e}",
                certificate.hash
            )
        })?;
        log_many("Certificate with hash='{}' is valid.", &certificate.hash);

        certificate = match &certificate.previous_hash {
            None => break,
            Some(hash) => fetch_certificate(aggregator_endpoint, hash).await?,
        }
    }

    Ok(certificate)
}

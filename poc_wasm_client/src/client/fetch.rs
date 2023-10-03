use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use super::{key_decode_hex, Certificate, CertificateMessage};

pub async fn fetch_url(url: &str) -> Result<String, String> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);
    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("WEB-SYS: request error: {e:?}"))?;
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

    let content = js_value
        .as_string()
        .ok_or_else(|| "WEB-SYS: given JSON is not a String".to_string())?;
    if content.is_empty() {
        return Err(format!("WEB-SYS: Could not fetch url {url}."));
    }

    Ok(content)
}

pub async fn fetch_certificate(
    aggregator_endpoint: &str,
    hash: &str,
) -> Result<Certificate, String> {
    let url = format!("{aggregator_endpoint}/certificate/{hash}");
    let content = fetch_url(&url).await?;

    let certificate_message: CertificateMessage = serde_json::from_str(&content).map_err(|_| {
        "SERDE-JSON: Could not deserialize CertificateMessage from given JSON ".to_string()
    })?;

    certificate_message.try_into()
}

pub async fn fetch_genesis_verification_key(
    genesis_verification_key_url: &str,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    let content = fetch_url(genesis_verification_key_url).await?;

    key_decode_hex(&content)
}

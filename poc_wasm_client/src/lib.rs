mod client;

use wasm_bindgen::prelude::*;

use client::*;
use web_sys::Window;

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

#[wasm_bindgen]
pub async fn run(
    aggregator_endpoint: &str,
    certificate_hash: &str,
    genesis_verification_key: &str,
) -> Result<(), JsValue> {
    let window = web_sys::window().expect("no global `window` exists");
    print_body(&window, "Verify certificate chain...");

    let chain_verification = verify_certificate_chain(
        aggregator_endpoint,
        certificate_hash,
        genesis_verification_key,
        &window,
    )
    .await;
    match &chain_verification {
        Ok(_) => {
            print_body(&window, "✅ certificate chain is verified!");
        }
        Err(e) => {
            print_body(
                &window,
                &format!("❌ certificate chain is invalid: {:?}", e),
            );
        }
    }

    chain_verification?;

    Ok(())
}

pub async fn verify_certificate_chain(
    aggregator_endpoint: &str,
    certificate_hash: &str,
    genesis_verification_key: &str,
    window: &Window,
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
        print_body(
            window,
            &format!("Certificate with hash='{}' is valid.", &certificate.hash),
        );

        certificate = match &certificate.previous_hash {
            None => break,
            Some(hash) => fetch_certificate(aggregator_endpoint, hash).await?,
        }
    }

    Ok(certificate)
}

fn print_body(window: &Window, message: &str) -> Result<(), JsValue> {
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");
    let val = document.create_element("div")?;
    body.append_child(&val)?;
    val.set_text_content(Some(message));

    Ok(())
}

mod client;

use client::*;
use wasm_bindgen::prelude::*;

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
pub async fn verify_mithril_certificate(
    aggregator_endpoint: &str,
    certificate_hash: &str,
    genesis_verification_key_url: &str,
) -> Result<(), JsValue> {
    print_window("<h2>Verify Mithril certificate:</h2>").unwrap();
    print_window(&format!(">> <b>Certificate hash</b>: {certificate_hash}")).unwrap();
    print_window(&format!(
        ">> <b>Aggregator endpoint</b>: {aggregator_endpoint}"
    ))
    .unwrap();
    print_window(&format!(
        ">> <b>Genesis verification key</b>: {genesis_verification_key_url}"
    ))
    .unwrap();
    print_window("<br/>").unwrap();

    let chain_verification = verify_certificate_chain(
        aggregator_endpoint,
        certificate_hash,
        genesis_verification_key_url,
    )
    .await;
    match &chain_verification {
        Ok(_) => {
            print_window("<h3>✅ Certificate chain is verified!!!</h3>").unwrap();
        }
        Err(e) => {
            print_window(&format!(
                "<h3>❌ Certificate chain is invalid: {:?}</h3>",
                e
            ))
            .unwrap();
        }
    }

    Ok(())
}

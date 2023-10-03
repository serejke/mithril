use wasm_bindgen::JsValue;

pub fn print_window(message: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| "WEB-SYS: no Window created!".to_string())?;
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");
    let val = document.create_element("div")?;
    body.append_child(&val)?;
    val.set_inner_html(message);

    Ok(())
}

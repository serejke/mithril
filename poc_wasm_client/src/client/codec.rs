use hex::FromHex;
use serde::de::DeserializeOwned;

pub fn key_decode_hex<T>(from: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let from_vec = Vec::from_hex(from).map_err(|e| {
        format!(
            "Key decode hex: can not turn hexadecimal value '{from}' into bytes, ERROR = '{e}'."
        )
    })?;

    serde_json::from_slice(from_vec.as_slice()).map_err(|e| {
        format!(
            "Key decode hex: can not deserialize to type '{}' from binary JSON, ERROR = '{e}'",
            std::any::type_name::<T>()
        )
    })
}

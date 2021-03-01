use serde::Serialize;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct TransferRequest {
    pub coin: String,
    pub size: f64,
    pub source: String,
    pub destination: String,
}

fn main() {
    let (key, secret) = get_key_and_secret();

    /*
     * Verify an authorised tx works
     */

    // Make request object
    let mut request = ureq::get("https://ftx.com/api/wallet/balances");
    // get time and sign for header
    let (time, sign) = get_time_and_sign(&secret, "GET", "/api/wallet/balances", "");
    // set headers
    request = request
        .set("FTX-KEY", &key)
        .set("FTX-TS", &time)
        .set("FTX-SIGN", &sign)
        .set("Content-Type", "application/json");
    // Call and verify response ok (200);
    let response = request.call();
    println!("{:?}", response);
    assert!(response.is_ok());

    /*
     * Try transfer
     */

    // Create the json object
    let tx_req = TransferRequest {
        coin: "USD".to_string(),
        size: 1.0,
        source: "main".to_string(),
        destination: "bot".to_string(),
    };
    // Convert it to a string
    let body = serde_json::to_string(&tx_req).unwrap();

    // Make request object
    let mut request = ureq::post("https://ftx.com/api/subaccounts/transfer");
    // get time and sign for header
    let (time, sign) = get_time_and_sign(&secret, "GET", "/api/subaccounts/transfer", &body);
    // set headers
    request = request
        .set("FTX-KEY", &key)
        .set("FTX-TS", &time)
        .set("FTX-SIGN", &sign)
        .set("Content-Type", "application/json");
    // Call and verify response ok (200);

    assert!(request.send_string(&body).is_ok(), "Did not transfer funds");
}

fn get_time_and_sign(secret: &str, method: &str, path: &str, body: &str) -> (String, String) {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let sign = get_sha256_hmac_as_hex_str(&format!("{}{}{}{}", time, method, path, body), secret);
    (time, sign)
}

pub fn get_sha256_hmac_as_hex_str(msg: &str, secret: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let sign = ring::hmac::sign(&key, msg.as_bytes());
    hex::encode(sign.as_ref())
}

fn get_key_and_secret() -> (String, String) {
    let val = load_json("key");
    println!("{:?} {}", val, val["key"].to_string());
    (
        val["key"].as_str().unwrap().to_string(),
        val["secret"].as_str().unwrap().to_string(),
    )
}

fn load_json(name: &str) -> Value {
    let path = format!("{}.json", name);
    let path = Path::new(&path);

    if let Ok(mut open_file) = File::open(path) {
        let mut contents: String = String::new();
        open_file
            .read_to_string(&mut contents)
            .unwrap_or_else(|_| panic!("Could not read {:?} contents", path));

        serde_json::from_str(&contents)
            .unwrap_or_else(|_| panic!("Could not deserialise {:?} contents to json", path))
    } else {
        panic!("Could not open {:?}", path);
    }
}

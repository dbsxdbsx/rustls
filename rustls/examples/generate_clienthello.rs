use rustls::RootCertStore;
use rustls::client::{ClientConfig, ClientConnection};
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;

fn main() {
    // Create a simple root cert store
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_slice(include_bytes!(
            "../../test-ca/rsa-2048/ca.der"
        )))
        .unwrap();

    // Build config with Chrome preset
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Apply browser-like policy with deterministic settings
    let policy = rustls::client::BrowserLikePolicy::chrome_latest()
        .with_extension_order_seed(0)
        .with_fixed_client_random([0u8; 32])
        .with_force_empty_session_id(true);

    config.set_hello_policy(Some(Arc::new(policy)));

    // Create connection
    let mut conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("example.com").unwrap(),
    )
    .unwrap();

    // Generate ClientHello
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();

    // Convert to hex
    let hex: String = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("{}", hex);
}

// Simple test to verify x25519-dalek 2.0 integration
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    println!("Testing x25519-dalek 2.0 integration...");

    // Generate a static secret
    let secret = StaticSecret::random();
    println!("Generated static secret: {} bytes", secret.to_bytes().len());

    // Generate public key from secret
    let public = PublicKey::from(&secret);
    println!("Generated public key: {} bytes", public.to_bytes().len());

    // Test key exchange
    let other_secret = StaticSecret::random();
    let other_public = PublicKey::from(&other_secret);

    let shared_secret1 = secret.diffie_hellman(&other_public);
    let shared_secret2 = other_secret.diffie_hellman(&public);

    assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
    println!("✅ Key exchange successful!");
    println!("Shared secret: {} bytes", shared_secret1.to_bytes().len());
}

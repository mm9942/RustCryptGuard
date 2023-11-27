mod keychain;
mod load_key;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

use keychain::Keychain;
use load_key::{Decapsulation, Encapsulation};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut kc = Keychain::new().await?;

    kc.save("keychain").await?;

    let public_key_path = "keychain/keychain.pub";
    let secret_key_path = "keychain/keychain.sec";
    let ciphertext_path = "keychain/keychain.ct";

    let mut encap = Encapsulation::load(public_key_path).await?;

    let mut decap = Decapsulation::new(kc.get_secret_key().await.unwrap(), encap.get_cipher().await.unwrap()).await;
    
    assert!(encap.get_shared_secret().await.unwrap() == decap.get_shared_secret().await.unwrap());
    println!("encap secret: {}\ndecap secret: {}\n", hex::encode(&encap.get_shared_secret().await.unwrap().as_bytes()), hex::encode(&decap.get_shared_secret().await.unwrap().as_bytes()));

    Ok(())
}

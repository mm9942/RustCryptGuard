use pqcrypto_kyber::kyber1024::{self, *};
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

use std::{
    error::Error,
    fmt,
    fs::{self},
    result::Result,
};


#[derive(Debug)]
pub enum KeychainError {
    IOError(std::io::Error),
    HexError(hex::FromHexError),
    EncapsulationError,
    DecapsulationError,
    WriteError(std::io::Error),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeychainError::IOError(ref err) => write!(f, "IO error: {}", err),
            KeychainError::HexError(ref err) => write!(f, "Hex error: {}", err),
            KeychainError::EncapsulationError => write!(f, "Encapsulation error"),
            KeychainError::DecapsulationError => write!(f, "Decapsulation error"),
            KeychainError::WriteError(ref err) => write!(f, "Write error: {}", err),
        }
    }
}

impl Error for KeychainError {}

pub struct File {
    pub path: String,
    pub data: Vec<u8>,
}

pub enum FileType {
    PublicKey,
    SecretKey,
    SharedSecret,
    Ciphertext,
}

//#[derive(Debug)]
pub struct Encapsulation {
    pub public_key: kyber1024::PublicKey,
    pub shared_secret: kyber1024::SharedSecret,
    pub ciphertext: kyber1024::Ciphertext,
}

//#[derive(Debug)]
pub struct Decapsulation {
    pub secret_key: kyber1024::SecretKey,
    pub ciphertext: kyber1024::Ciphertext,
    pub shared_secret: kyber1024::SharedSecret,
}

impl Encapsulation {
    pub async fn load(path: &str) -> Result<Self, KeychainError> {
        let public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
        
        println!("Successfully loaded public key.");
        
        Ok(Self::new(public_key).await)
    }

    pub async fn new(public_key: kyber1024::PublicKey) -> Self {
        let (shared_secret, ciphertext) = encapsulate(&public_key);
        
        println!("Encapsulation successful.");
        
        Self {
            public_key,
            shared_secret,
            ciphertext,
        }
    }

    pub async fn load_public_key(&mut self, path: &str) -> Result<kyber1024::PublicKey, KeychainError> {
        let public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
        
        println!("Successfully loaded public key.");
        let _ = self.public_key == public_key;
        Ok(self.public_key)
    }

    pub async fn load_cipher(&mut self, path: &str) -> Result<kyber1024::Ciphertext, KeychainError> {let _public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let cipher_bytes = File::load(path, FileType::Ciphertext).await.unwrap();
        let cipher = Ciphertext::from_bytes(&cipher_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
    
        println!("Successfully loaded public key.");
        let _ = self.ciphertext == cipher;
        Ok(self.ciphertext)
    }

    pub async fn load_shared_secret(&mut self, path: &str) -> Result<kyber1024::SharedSecret, KeychainError> {
        let shared_secret_bytes = File::load(path, FileType::SharedSecret).await.unwrap();
        let shared_secret = SharedSecret::from_bytes(&shared_secret_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
    
        println!("Successfully loaded public key.");
        let _ = self.shared_secret == shared_secret;
        Ok(self.shared_secret)
    }

    pub async fn get_public_key(&mut self) -> Result<kyber1024::PublicKey, KeychainError> {
        Ok(self.public_key)
    }


    pub async fn get_cipher(&mut self) -> Result<kyber1024::Ciphertext, KeychainError> {
        Ok(self.ciphertext)
    }

    pub async fn get_shared_secret(&mut self) -> Result<kyber1024::SharedSecret, KeychainError> {
        Ok(self.shared_secret)
    }
}

impl Decapsulation {
    pub async fn load(sec_path: &str, cipher_path: &str) -> Result<Self, KeychainError> {
        let secret_key_bytes = File::load(sec_path, FileType::SecretKey).await.unwrap();
        let secret_key = SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        println!("Successfully loaded secret key.");

        let ciphertext_bytes = File::load(cipher_path, FileType::Ciphertext).await.unwrap();
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        println!("Successfully loaded ciphertext.");

        Ok(Self::new(secret_key, ciphertext).await)
    }

    pub async fn new(secret_key: kyber1024::SecretKey, ciphertext: kyber1024::Ciphertext) -> Self {
        let shared_secret = decapsulate(&ciphertext, &secret_key);
        
        println!("Decapsulation successful.");
        
        Self {
            secret_key,
            ciphertext,
            shared_secret,
        }
    }


    pub async fn load_secret_key(&mut self, path: &str) -> Result<kyber1024::SecretKey, KeychainError> {
        let secret_key_bytes = File::load(path, FileType::SecretKey).await.unwrap();
        let secret_key = SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
        
        println!("Successfully loaded public key.");
        let _ = self.secret_key == secret_key;
        Ok(self.secret_key)
    }

    pub async fn load_cipher(&mut self, path: &str) -> Result<kyber1024::Ciphertext, KeychainError> {let _public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let cipher_bytes = File::load(path, FileType::Ciphertext).await.unwrap();
        let cipher = Ciphertext::from_bytes(&cipher_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
    
        println!("Successfully loaded public key.");
        let _ = self.ciphertext == cipher;
        Ok(self.ciphertext)
    }

    pub async fn load_shared_secret(&mut self, path: &str) -> Result<kyber1024::SharedSecret, KeychainError> {
        let shared_secret_bytes = File::load(path, FileType::SharedSecret).await.unwrap();
        let shared_secret = SharedSecret::from_bytes(&shared_secret_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
    
        println!("Successfully loaded public key.");
        let _ = self.shared_secret == shared_secret;
        Ok(self.shared_secret)
    }

    pub async fn get_secret_key(&mut self) -> Result<kyber1024::SecretKey, KeychainError> {
        Ok(self.secret_key)
    }


    pub async fn get_cipher(&mut self) -> Result<kyber1024::Ciphertext, KeychainError> {
        Ok(self.ciphertext)
    }

    pub async fn get_shared_secret(&mut self) -> Result<kyber1024::SharedSecret, KeychainError> {
        Ok(self.shared_secret)
    }
}

impl File {
    pub async fn load(path: &str, file_type: FileType) -> Result<Vec<u8>, KeychainError> {
        let file_content = fs::read_to_string(path)
            .map_err(KeychainError::IOError)?;

        let (start_label, end_label) = match file_type {
            FileType::PublicKey => ("-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----"),
            FileType::SecretKey => ("-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----"),
            FileType::SharedSecret => ("-----BEGIN SHARED SECRET-----\n", "\n-----END SHARED SECRET-----"),
            FileType::Ciphertext => ("-----BEGIN CIPHERTEXT-----\n", "\n-----END CIPHERTEXT-----"),
        };

        let start = file_content.find(start_label)
            .ok_or_else(|| KeychainError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "Start label not found")))?;
        let end = file_content.find(end_label)
            .ok_or_else(|| KeychainError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "End label not found")))?;

        let content = &file_content[start + start_label.len()..end];
        
        hex::decode(content)
            .map_err(KeychainError::HexError)
    }
}

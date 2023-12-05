use pqcrypto_kyber::kyber1024::{self, *};
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

use std::{
    error::Error,
    fmt,
    fs::{self},
    result::Result,
    env,
};

use aes::Aes256;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

use sha2::Sha256;
use hmac::{Hmac, Mac};

use crate::load_key::{FileType, File};

#[derive(Debug)]
pub enum KeychainError {
    IOError(std::io::Error),
    HexError(hex::FromHexError),
    EncapsulationError,
    DecapsulationError,
    WriteError(std::io::Error),
    HmacVerificationError,
    HexDecodingError(String),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeychainError::IOError(ref err) => write!(f, "IO error: {}", err),
            KeychainError::HexError(ref err) => write!(f, "Hex error: {}", err),
            KeychainError::EncapsulationError => write!(f, "Encapsulation error"),
            KeychainError::DecapsulationError => write!(f, "Decapsulation error"),
            KeychainError::WriteError(ref err) => write!(f, "Write error: {}", err),
            KeychainError::HmacVerificationError => write!(f, "HMAC Verification Failed: The data's integrity or authenticity could not be verified. This may indicate that the data has been tampered with or corrupted!"),
            KeychainError::HexDecodingError(ref err) => write!(f, "Hex decoding error: {}", err),

        }
    }
}

impl From<std::io::Error> for KeychainError {
    fn from(error: std::io::Error) -> Self {
        KeychainError::IOError(error)
    }
}


pub enum EncryptionType {
    EncryptFile,
    EncryptMessage,
    EncryptDrive,
}

pub enum DecryptionType {
    DecryptFile,
    DecryptMessage,
    DecryptDrive,
}

pub enum ExecutionArgs {
    Save,
    Print,
}
pub struct Keychain {
    public_key: kyber1024::PublicKey,
    secret_key: kyber1024::SecretKey,
    shared_secret: kyber1024::SharedSecret,
    ciphertext: kyber1024::Ciphertext,
}

impl Keychain {
    pub async fn new() -> Result<Self, KeychainError> {
        let (pk, sk) = keypair();
        let (ss, ct) = encapsulate(&pk);
        Ok(Self {
            public_key: pk,
            secret_key: sk,
            shared_secret: ss,
            ciphertext: ct,
        })
    }

    pub async fn show(&self) -> Result<(), KeychainError> {
        let ss2 = decapsulate(&self.ciphertext, &self.secret_key);
        println!("Public Key: {}\n\nSecret Key: {}\n\nShared secret: {}\n\nDecapsulated shared secret: {}", 
                 hex::encode(&self.public_key.as_bytes()), 
                 hex::encode(&self.secret_key.as_bytes()), 
                 hex::encode(&self.shared_secret.as_bytes()), 
                 hex::encode(&ss2.as_bytes()));
        Ok(())
    }

    pub async fn save(&self, title: &str) -> Result<(), KeychainError> {
        let public_key_path = format!("{}/{}.pub", title, title);
        let secret_key_path = format!("{}/{}.sec", title, title);
        let shared_secret_path = format!("{}/{}.ss", title, title);
        let ciphertext_path = format!("{}/{}.ct", title, title);

        if !std::path::Path::new(&title).exists() {
            let _ = std::fs::create_dir(title);
        }

        fs::write(
            &public_key_path, 
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                hex::encode(&self.public_key.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        fs::write(
            &secret_key_path, 
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                hex::encode(&self.secret_key.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        fs::write(
            &shared_secret_path, 
            format!(
                "-----BEGIN SHARED SECRET-----\n{}\n-----END SHARED SECRET-----",
                hex::encode(&self.shared_secret.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        fs::write(
            &ciphertext_path, 
            format!(
                "-----BEGIN CIPHERTEXT-----\n{}\n-----END CIPHERTEXT-----",
                hex::encode(&self.ciphertext.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        println!(
            "\nPlease write down: {}\n\nKeychain saved successfully.\n",
            hex::encode(&self.shared_secret.as_bytes())
        );
        Ok(())
    }

    pub async fn load_public_key(&mut self, path: &str) -> Result<kyber1024::PublicKey, KeychainError> {
        let public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;
        
        println!("Successfully loaded public key.");
        let _ = self.public_key == public_key;
        Ok(self.public_key)
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

    pub async fn get_public_key(&mut self) -> Result<kyber1024::PublicKey, KeychainError> {
        Ok(self.public_key)
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

    fn generate_unique_filename(base_path: &str, extension: &str) -> String {
        let mut counter = 1;
        let mut unique_path = format!("{}{}", base_path, extension);
        while std::path::Path::new(&unique_path).exists() {
            unique_path = format!("{}_{}{}", base_path, counter, extension);
            counter += 1;
        }
        unique_path
    }

    fn generate_original_filename(encrypted_path: &str) -> String {
        let path = std::path::Path::new(encrypted_path);
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let mut file_name = path.file_stem().unwrap().to_str().unwrap().to_string();

        // Remove appended numbers and extensions like _1, _2, etc.
        if let Some(index) = file_name.rfind('_') {
            if file_name[index + 1..].chars().all(char::is_numeric) {
                file_name.truncate(index);
            }
        }

        format!("{}/{}", dir.display(), file_name)
    }

    fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn append_hmac(encrypted_data: Vec<u8>, hmac: Vec<u8>) -> Vec<u8> {
        [encrypted_data, hmac].concat()
    }

    fn verify_hmac(key: &[u8], data_with_hmac: &[u8], hmac_len: usize) -> Result<Vec<u8>, &'static str> {
        if data_with_hmac.len() < hmac_len {
            return Err("Data is too short");
        }

        let (data, hmac) = data_with_hmac.split_at(data_with_hmac.len() - hmac_len);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");

        mac.update(data);
        
        mac.verify_slice(hmac).map_err(|_| "HMAC verification failed")?;
        Ok(data.to_vec())
    }


    pub async fn encrypt_with_shared_secret(path: &str, encrypt: &str, encryption_type: EncryptionType, exec_args: ExecutionArgs, hmac_key: &[u8]) -> Result<(), KeychainError> {
        let shared_secret_bytes = File::load(path, FileType::SharedSecret).await.unwrap();
        let shared_secret = kyber1024::SharedSecret::from_bytes(&shared_secret_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;

        let path = std::path::Path::new(path);
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let filename = path.file_stem().unwrap().to_str().unwrap();

        let key = GenericArray::clone_from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256::new(&key);
        //let hmac_key: &[u8] = format!(b"{}", pass);

        match encryption_type {
            EncryptionType::EncryptFile => {
                let mut file_data = fs::read(encrypt)?;
                while file_data.len() % 16 != 0 {
                    file_data.push(0);
                }
                for chunk in file_data.chunks_mut(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }
                let hmac = Self::generate_hmac(hmac_key, &file_data);
                let encrypted_with_hmac = Self::append_hmac(file_data, hmac);
                let encrypted_file_path = Self::generate_unique_filename(encrypt, ".enc");
                fs::write(encrypted_file_path, encrypted_with_hmac)?;
                },
            EncryptionType::EncryptMessage => {
                let mut message = encrypt.as_bytes().to_vec();
                while message.len() % 16 != 0 {
                    message.push(0);
                }

                for chunk in message.chunks_mut(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }

                let hmac = Self::generate_hmac(hmac_key, &message);
                let encrypted_with_hmac = Self::append_hmac(message, hmac);

                let message_path = Self::generate_unique_filename("message", ".enc");
                let hex_encrypted_with_hmac = hex::encode(encrypted_with_hmac);

                // Format the hex-encoded message with BEGIN and END tags
                let message_hex = format!(
                    "-----BEGIN ENCRYPTED MESSAGE-----\n{}\n-----END ENCRYPTED MESSAGE-----",
                    hex_encrypted_with_hmac
                );

                match exec_args {
                    ExecutionArgs::Save => {
                        let message_path = Self::generate_unique_filename("message", ".enc");
                        fs::write(&message_path, &message_hex).map_err(KeychainError::WriteError)?;
                    },
                    ExecutionArgs::Print => {
                        println!("{}", message_hex);
                    },
                    _ => {
                        eprintln!("Wrong or non-existent enum type selected");
                    }
                }
            },
            EncryptionType::EncryptDrive => {
                // Placeholder for drive encryption
                // Note: Drive encryption is a complex process and needs a comprehensive approach.
                // ...
            },
            _ => {
                // handling error
            }
        }

        Ok(())
    }

    pub async fn encrypt_with_public_key(path: &str, encrypt: &str, encryption_type: EncryptionType, exec_args: ExecutionArgs, hmac_key: &[u8]) -> Result<(), KeychainError> {
        let public_key_bytes = File::load(path, FileType::PublicKey).await.unwrap();
        let public_key = kyber1024::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| KeychainError::EncapsulationError)?;

        let (shared_secret, ciphertext) = kyber1024::encapsulate(&public_key);

        let path = std::path::Path::new(path);
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let filename = path.file_stem().unwrap().to_str().unwrap();

        let mut shared_secret_base_path = format!("{}/{}", dir.display(), filename);
        let mut ciphertext_base_path = format!("{}/{}", dir.display(), filename);

        let shared_secret_path = Self::generate_unique_filename(&shared_secret_base_path, ".ss");
        let ciphertext_path = Self::generate_unique_filename(&ciphertext_base_path, ".ct");

        fs::write(
            &shared_secret_path, 
            format!(
                "-----BEGIN SHARED SECRET-----\n{}\n-----END SHARED SECRET-----",
                hex::encode(&shared_secret.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        fs::write(
            &ciphertext_path, 
            format!(
                "-----BEGIN CIPHERTEXT-----\n{}\n-----END CIPHERTEXT-----",
                hex::encode(&ciphertext.as_bytes())
            )
        ).map_err(KeychainError::WriteError)?;

        let key = GenericArray::clone_from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256::new(&key);
        
        //let hmac_key: &[u8] = format!(b"{}", pass);

        match encryption_type {
            EncryptionType::EncryptFile => {
                let mut file_data = fs::read(encrypt)?;
                while file_data.len() % 16 != 0 {
                    file_data.push(0);
                }
                for chunk in file_data.chunks_mut(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }
                let hmac = Self::generate_hmac(hmac_key, &file_data);
                let encrypted_with_hmac = Self::append_hmac(file_data, hmac);
                let encrypted_file_path = Self::generate_unique_filename(encrypt, ".enc");
                fs::write(encrypted_file_path, encrypted_with_hmac)?;
                },
            EncryptionType::EncryptMessage => {
                let mut message = encrypt.as_bytes().to_vec();
                while message.len() % 16 != 0 {
                    message.push(0);
                }

                for chunk in message.chunks_mut(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }

                let hmac = Self::generate_hmac(hmac_key, &message);
                let encrypted_with_hmac = Self::append_hmac(message, hmac);

                let message_path = Self::generate_unique_filename("message", ".enc");
                let hex_encrypted_with_hmac = hex::encode(encrypted_with_hmac);

                // Format the hex-encoded message with BEGIN and END tags
                let message_hex = format!(
                    "-----BEGIN ENCRYPTED MESSAGE-----\n{}\n-----END ENCRYPTED MESSAGE-----",
                    hex_encrypted_with_hmac
                );

                match exec_args {
                    ExecutionArgs::Save => {
                        let message_path = Self::generate_unique_filename("message", ".enc");
                        fs::write(&message_path, &message_hex).map_err(KeychainError::WriteError)?;
                    },
                    ExecutionArgs::Print => {
                        println!("{}", message_hex);
                    },
                    _ => {
                        eprintln!("Wrong or non-existent enum type selected");
                    }
                }
            },
            EncryptionType::EncryptDrive => {
                // Placeholder for drive encryption
                // Note: Drive encryption is a complex process and needs a comprehensive approach.
                // ...
            },
            _ => {
                // handling error
            }
        }

        Ok(())
    }
    
    pub async fn load_encrypted_message(&self, path: &str) -> Result<Vec<u8>, KeychainError> {
        let message_data = fs::read_to_string(path).map_err(KeychainError::IOError)?;

        // Extract the hexadecimal part between the tags
        let hex_message = message_data
            .split("-----BEGIN ENCRYPTED MESSAGE-----\n")
            .nth(1)
            .and_then(|s| s.split("\n-----END ENCRYPTED MESSAGE-----").next())
            .ok_or_else(|| KeychainError::HexDecodingError("Failed to extract hex string".to_string()))?;

        // Convert back from hex to bytes
        hex::decode(hex_message).map_err(|e| KeychainError::HexDecodingError(e.to_string()))
    }

    pub async fn decrypt_with_secret_key(
        &self,
        encrypted_path: &str,
        ciphertext_path: &str,
        secret_key_path: &str,
        decryption_type: DecryptionType,
        hmac_key: &[u8]
    ) -> Result<(), KeychainError> {
        let ciphertext_bytes = File::load(ciphertext_path, FileType::Ciphertext).await.unwrap();
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        let secret_key_bytes = File::load(secret_key_path, FileType::SecretKey).await.unwrap();
        let secret_key = SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        let shared_secret = decapsulate(&ciphertext, &secret_key);
        let key = GenericArray::clone_from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256::new(&key);
        
        //let hmac_key: &[u8] = format!(b"{}", pass);
        const HMAC_LEN: usize = 32;


        match decryption_type {
            DecryptionType::DecryptFile => {
                let encrypted_with_hmac = fs::read(encrypted_path)?;
                let file_data_with_hmac = Self::verify_hmac(hmac_key, &encrypted_with_hmac, HMAC_LEN).unwrap();

                let mut file_data = Vec::new();
                for chunk in file_data_with_hmac.chunks(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.decrypt_block(&mut block);
                    file_data.extend_from_slice(&block);
                }

                while file_data.last() == Some(&0) {
                    file_data.pop();
                }

                let decrypted_file_path = Self::generate_original_filename(encrypted_path);
                fs::write(decrypted_file_path, file_data)
                    .map_err(KeychainError::WriteError)?;

            },  
            DecryptionType::DecryptMessage => {
                let encrypted_with_hmac_hex = self.load_encrypted_message(encrypted_path).await?;

                let message = Self::verify_hmac(hmac_key, &encrypted_with_hmac_hex, HMAC_LEN)
                    .map_err(|_| KeychainError::HmacVerificationError)?;

                let mut decrypted_message = Vec::new();

                for chunk in message.chunks(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.decrypt_block(&mut block);
                    decrypted_message.extend_from_slice(&block);
                }

                while decrypted_message.last() == Some(&0) {
                    decrypted_message.pop();
                }

                let decrypted_message_str = String::from_utf8(decrypted_message)
                    .map_err(|_| KeychainError::DecapsulationError)?;
                println!("Decrypted message: {}", decrypted_message_str);
            },
            DecryptionType::DecryptDrive => {
                // Logic for drive decryption would go here
            },
            _ => {
                // handling error
            }
        }

        Ok(())
    }

    pub async fn decrypt_message(
        &self,
        message: &str,
        ciphertext_path: &str,
        secret_key_path: &str,
        hmac_key: &[u8]
    ) -> Result<(), KeychainError> {
        let ciphertext_bytes = File::load(ciphertext_path, FileType::Ciphertext).await.unwrap();
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;
        let secret_key_bytes = File::load(secret_key_path, FileType::SecretKey).await.unwrap();
        let secret_key = SecretKey::from_bytes(&secret_key_bytes)
            .map_err(|_| KeychainError::DecapsulationError)?;

        let shared_secret = decapsulate(&ciphertext, &secret_key);
        let key = GenericArray::clone_from_slice(&shared_secret.as_bytes()[..32]);
        let cipher = Aes256::new(&key);
        const HMAC_LEN: usize = 32;

        let hex_message = if message.contains("-----BEGIN ENCRYPTED MESSAGE-----") && message.contains("-----END ENCRYPTED MESSAGE-----") {
            message.split("-----BEGIN ENCRYPTED MESSAGE-----\n")
                   .nth(1)
                   .and_then(|s| s.split("\n-----END ENCRYPTED MESSAGE-----").next())
                   .ok_or_else(|| KeychainError::HexDecodingError("Failed to extract hex string".to_string()))?
        } else {
            message
        };

        let message_bytes = hex::decode(hex_message)
            .map_err(|e| KeychainError::HexDecodingError(e.to_string()))?;
        let data_with_hmac = Self::verify_hmac(hmac_key, &message_bytes, HMAC_LEN)
            .map_err(|_| KeychainError::HmacVerificationError)?;

        let mut decrypted_message = Vec::new();
        for chunk in data_with_hmac.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            decrypted_message.extend_from_slice(&block);
        }

        while decrypted_message.last() == Some(&0) {
            decrypted_message.pop();
        }

        let decrypted_message_str = String::from_utf8(decrypted_message)
            .map_err(|_| KeychainError::DecapsulationError)?;

        println!("Decrypted message: {}", decrypted_message_str);
        Ok(())
    }

}

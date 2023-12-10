mod keychain;
mod load_key;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

use crate::keychain::{Keychain, EncryptionType, DecryptionType, ExecutionArgs};
use crate::load_key::{Decapsulation, Encapsulation};
use tokio;
pub use clap::{
    self,
    Arg,
    Command,
    arg,
    Parser,
    command,
    builder::OsStr,
    ArgAction
};

async fn cli() -> Command {
    Command::new("pqencrypt")
        .about("A post-quantum encryption tool")
        .long_about("A command-line tool for post-quantum encryption using Kyber1024")
        .author("mm29942, mm29942@pm.me")
        .display_name("PostQuantum Encrypt")
        .arg(arg!(-l --list "List all saved keyfiles.").action(ArgAction::SetTrue).required(false))
        .subcommand(
            Command::new("new")
                .about("Create new encryption keys")
                .arg(arg!(-n --name <NAME> "Set the keyname you want to use").required(true))
                .arg(arg!(-p --path <PATH> "Set the path to save the keyfiles into.").required(false).default_value("."))
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a file, message or DataDrive using the public key")
                .arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to derive encryption key").required(true))
                .arg(arg!(-u --public <PUBLIC> "Path to the public key file for encryption").required(false))
                .arg(arg!(-s --save "Saves the encrypted output to a file. If not specified, the output will be printed to the console.").action(ArgAction::SetTrue).required(false))
                .arg(arg!(-f --file <FILE> "Select the file you want to encrypt.").required(false))
                .arg(arg!(-m --message <MESSAGE> "Define the message you want to encrypt.").required(false))
                .arg(arg!(-d --drive <DRIVE> "Select the DataDrive you want to encrypt").required(false))
                .arg(arg!(--dir <DIR> "Select the directory, where you want to save the encrypted file/ message").required(false))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt encrypted files, messages or DataDrive using the secret key and the ciphertext")
                .arg(arg!(-p --passphrase <PASSPHRASE> "Passphrase to derive decryption key").required(true))
                .arg(arg!(-s --secret <SECRET> "Path to the secret key file for decryption").required(true))
                .arg(arg!(-c --ciphertext <CIPHERTEXT> "Select the ciphertext which is needed to retrieve the shared secret").required(true))
                .arg(arg!(-f --file <FILE> "Select the file you want to decrypt.").required(false))
                .arg(arg!(-m --message <MESSAGE> "Define the message you want to decrypt.").required(false))
                .arg(arg!(-d --drive <DRIVE> "Select the DataDrive you want to decrypt").required(false))
        )
}


struct encrypt {
    public_key: String,
    ciphertext: String,
    shared_secret: String,
}

impl encrypt {
    fn new() -> Self {
        Self {
            public_key: String::new(),
            ciphertext: String::new(),
            shared_secret: String::new(),
        }
    }

    fn set_public_key(&mut self, public_key: String) {
        self.public_key = public_key;
    }

    fn set_ciphertext(&mut self, ciphertext: String) {
        self.ciphertext = ciphertext;
    }

    fn set_shared_secret(&mut self, shared_secret: String) {
        self.shared_secret = shared_secret;
    }
}

struct decrypt {
    secret_key: String,
    ciphertext: String,
    shared_secret: String,
}

impl decrypt {
    fn new() -> Self {
        Self {
            secret_key: String::new(),
            ciphertext: String::new(),
            shared_secret: String::new(),
        }
    }

    fn set_secret_key(&mut self, secret_key: String) {
        self.secret_key = secret_key;
    }

    fn set_ciphertext(&mut self, ciphertext: String) {
        self.ciphertext = ciphertext;
    }

    fn set_shared_secret(&mut self, shared_secret: String) {
        self.shared_secret = shared_secret;
    }
}


async fn check() {
    let matches = cli().await.get_matches();

    let _public = String::new();
    let _secret = String::new();
    let _ciphertext = String::new();
    let _shared = String::new();
    let _file = String::new();
    let _message = String::new();
    let _drive = String::new();
    let _name = String::new();
    let _path = String::new();
    let _key = String::new();

    if let Some(sub_matches) = matches.subcommand_matches("new") {
        let keyname = sub_matches.get_one::<String>("name");
        let keypath = sub_matches.get_one::<String>("path");
        let mut keychain = Keychain::new().await.expect("Failed to initialize keychain");
        let _ = keychain.show().await;
        let _ = keychain.save(keypath.unwrap().as_str(), keyname.unwrap().as_str()).await;
    }
    if let Some(sub_matches) = matches.subcommand_matches("encrypt") {
        let mut is_message = false;

        let hmac_key = sub_matches.get_one::<String>("passphrase").expect("HMAC key is required");
        let hmac_key_bytes = hmac_key.as_bytes();

        let encrypt_option = if sub_matches.contains_id("file") {
            (sub_matches.get_one::<String>("file").unwrap().clone(), EncryptionType::EncryptFile)
        } else if sub_matches.contains_id("message") {
            is_message = true;
            (sub_matches.get_one::<String>("message").unwrap().clone(), EncryptionType::EncryptMessage)
        } else if sub_matches.contains_id("drive") {
            (sub_matches.get_one::<String>("drive").unwrap().clone(), EncryptionType::EncryptDrive)
        } else {
            eprintln!("Error: No encryption option specified.");
            return;
        };

        // Determine execution action
        let exec_action = if is_message && !sub_matches.get_flag("save") {
            ExecutionArgs::Print
        } else {
            ExecutionArgs::Save
        };

        // Initialize keychain
        let keychain = Keychain::new().await.expect("Failed to initialize keychain");

        // Check for public key or shared secret
        if let Some(public_key_path) = sub_matches.get_one::<String>("public") {
            Keychain::encrypt_with_public_key(
                public_key_path,
                encrypt_option.0.as_str(),
                encrypt_option.1,
                exec_action,
                hmac_key_bytes
            ).await.expect("Encryption failed");
            println!("Encryption completed with the public key: {}", public_key_path);

        } else if let Some(shared_secret_path) = sub_matches.get_one::<String>("shared_secret") {
            Keychain::encrypt_with_shared_secret(
                shared_secret_path,
                encrypt_option.0.as_str(),
                encrypt_option.1,
                exec_action,
                hmac_key_bytes
            ).await.expect("Encryption failed using shared secret");
            println!("Encryption completed using the shared secret: {}", shared_secret_path);
        } else {
            eprintln!("Error: Either a public key or a shared secret must be provided.");
        }
    }
    if let Some(sub_matches) = matches.subcommand_matches("decrypt") {
        let secret_key_path = sub_matches.get_one::<String>("secret").expect("Secret key path is required");
        let ciphertext_path = sub_matches.get_one::<String>("ciphertext").expect("Ciphertext path is required");
        

        let keychain = Keychain::new().await.expect("Failed to initialize keychain");

        let hmac_key = sub_matches.get_one::<String>("passphrase").expect("HMAC key is required");
        let hmac_key_bytes = hmac_key.as_bytes();

        let decrypt_option = if sub_matches.contains_id("file") {
            let file_path = sub_matches.get_one::<String>("file").unwrap().clone();
            (file_path, DecryptionType::DecryptFile)
        } else if sub_matches.contains_id("message") {
            let message_path = sub_matches.get_one::<String>("message").unwrap().clone();
            (message_path, DecryptionType::DecryptMessage)
        } else if sub_matches.contains_id("drive") {
            let drive_path = sub_matches.get_one::<String>("drive").unwrap().clone();
            (drive_path, DecryptionType::DecryptDrive)
        } else {
            eprintln!("Error: No decryption option specified.");
            return;
        };

        let message = sub_matches.get_one::<String>("message").unwrap().clone();
        keychain.decrypt_message(
            &message, 
            ciphertext_path.as_str(), 
            secret_key_path.as_str(),
            hmac_key_bytes
        ).await.expect("Decryption failed");
    }

    if matches.get_flag("list") {
    }


}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    check().await;
    Ok(())
}

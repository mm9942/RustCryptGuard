# RustCryptGuard

## Overview
RustCryptGuard is a Rust application demonstrating the implementation of post-quantum cryptography, specifically using the Kyber1024 algorithm for Key Encapsulation Mechanism (KEM). It provides functionalities for generating, encapsulating, and decapsulating keys, utilizing the `pqcrypto_kyber` crate. The application is structured into two main modules, `keychain` and `load_key`, along with `main.rs` for execution.

## Modules

### `keychain.rs`
This module manages key operations and cryptographic processes, including:
- `Keychain` struct comprising public key, secret key, shared secret, and ciphertext.
- Key generation and storage capabilities.
- Display of key information.
- Implementation of AES256 for encryption and HMAC SHA-256 for data integrity and authentication.
- Encapsulation and decapsulation functions using shared or public keys.
- Custom error handling through the `KeychainError` enum.

### `load_keys.rs`
Focuses on the encapsulation and decapsulation aspects:
- `Encapsulation` and `Decapsulation` structs for managing cryptographic operations.
- Functions for loading keys from files and performing encapsulation/decapsulation with Kyber1024.
- Similar error handling approach as `keychain.rs`.

## Main Functionality (`main.rs`)
Coordinates the application's primary functions:
- Initializes `Keychain`.
- Manages key generation, storage, and cryptographic tasks.
- Implements CLI argument parsing and command definitions using `clap`.

## Usage
- Ensure Rust and `tokio` runtime are installed.
- Clone the repository and navigate to the project directory.
- Build and run the application with `cargo run`.
- Use the CLI interface for various operations like key generation, encryption, and decryption.

## Dependencies Overview
- `pqcrypto_kyber`: Implements the Kyber1024 post-quantum algorithm.
- `pqcrypto_traits`: Provides traits for KEM operations.
- `hex`: Handles hexadecimal encoding and decoding.
- `tokio`: Asynchronous runtime for efficient task management.
- `aes`: Facilitates AES256 encryption.
- `sha2`: Provides SHA-256 hashing capabilities.
- `hmac`: Ensures data integrity and authentication with HMAC.
- `clap`: Creates an intuitive CLI interface for user interaction.

## Error Handling
The application uses a custom `KeychainError` enum for comprehensive error management, ensuring robustness in various scenarios like I/O errors, hex encoding issues, and cryptographic errors.

## License

This project is licensed under the GNU General Public License (GPL) version 3 or later.

### GNU General Public License (GPL) Overview
- The GPL is a copyleft license, which means that any derivative work must be distributed under the same or compatible license terms. This ensures that the content and any modifications of it remain free and open.
- Under this license, anyone who modifies and shares the project, or any derivative works, must also make their source code available under the same terms.
- The GPL license guarantees users the freedom to run, study, share, and modify the software. 

### How This Affects Contributors and Users
- **For Contributors**: If you contribute to this project, you are agreeing to share your modifications under the GPL terms. This fosters an open and collaborative environment where improvements are shared with the community.
- **For Users**: You can use and modify this software for personal or commercial purposes. However, if you distribute the modified software, you must do so under the same GPL terms, and you must also disclose your source code.

### Maintaining Attribution to the Original Author
- While the GPL does not specifically require attribution to the original author in a prominent way (like some permissive licenses do), it ensures that the original licensing terms and notices are preserved, acknowledging the initial work of the author.

### Further Information
- Full text of the license can be found [here](https://www.gnu.org/licenses/gpl-3.0.html).

**Note**: For detailed understanding and usage instructions, look into the code comments and documentation within the application.

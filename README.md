# RustCryptGuard

## Overview
This Rust application demonstrates the use of post-quantum cryptography, specifically using the Kyber1024 algorithm for Key Encapsulation Mechanism (KEM). It allows for the generation, encapsulation, and decapsulation of keys, utilizing the `pqcrypto_kyber` crate. The application consists of two main modules: `keychain` and `load_key`, along with a `main.rs` for execution.

## Modules

### `keychain.rs`
This module defines the `Keychain` struct, which includes a public key, a secret key, a shared secret, and a ciphertext. The `Keychain` provides functionalities to:
- Generate a new keychain with public and secret keys.
- Save the keys to files with specified titles.
- Display key information.

### `load_keys.rs`
This module contains two structs, `Encapsulation` and `Decapsulation`, each responsible for the encapsulation and decapsulation processes, respectively. These structs handle:
- Loading public and secret keys from files.
- Performing encapsulation and decapsulation using the Kyber1024 algorithm.

## Main Functionality
In `main.rs`, the application:
- Generates a new `Keychain`.
- Saves the generated keys to a designated directory.
- Performs encapsulation and decapsulation operations.
- Displays the results of these operations.

## Usage
To use this application:
1. Ensure you have Rust and the `tokio` runtime installed.
2. Clone the repository and navigate to the project directory.
3. Build and run the application using `cargo run`.
4. The generated keys and their information will be displayed and saved in the specified directory.

## Dependencies
- `pqcrypto_kyber`: For the Kyber1024 post-quantum algorithm.
- `pqcrypto_traits`: Provides traits for KEM operations.
- `hex`: To encode and decode hexadecimal representations.
- `tokio`: Asynchronous runtime.

## Error Handling
The application includes a custom `KeychainError` enum for handling various errors, such as I/O errors, hex decoding errors, and encapsulation/decapsulation related errors.

## License
Specify your licensing information here.

## Contributing
Guidelines for contributing to the project can be outlined here.

---

**Note**: This readme provides a basic overview of the application's structure and functionality. Additional documentation and comments in the code should be referred to for detailed understanding and usage.

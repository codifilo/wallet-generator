use bip39::{Language, Mnemonic};
use bip32::{DerivationPath as Bip32Path}; // Renamed for clarity
use slip10::{BIP32Path as Slip10Path, derive_key_from_path, Curve}; // Renamed for clarity
use k256::{ecdsa::VerifyingKey, pkcs8::der};
use sha2::{Digest, Sha256};
use ripemd::{Ripemd160};
use tiny_keccak::{Keccak, Hasher};

fn main() {
    let seed_phrase = "year teach pizza vibrant wing panic scene paper one blouse load aim";
    let passphrase = "";
    let count = 5;

    generate(seed_phrase, passphrase, 1, Chain::Bitcoin, DerivationPathFormat::Bip44Root);
    generate(seed_phrase, passphrase, count, Chain::Bitcoin, DerivationPathFormat::Bip44Change);
    generate(seed_phrase, passphrase, count, Chain::Bitcoin, DerivationPathFormat::Bip44Standard);
    generate(seed_phrase, passphrase, 1, Chain::Ethereum, DerivationPathFormat::Bip44Root);
    generate(seed_phrase, passphrase, count, Chain::Ethereum, DerivationPathFormat::Bip44Change);
    generate(seed_phrase, passphrase, count, Chain::Ethereum, DerivationPathFormat::Bip44Standard);
    generate(seed_phrase, passphrase, 1, Chain::Solana, DerivationPathFormat::Bip44Root);
    generate(seed_phrase, passphrase, count, Chain::Solana, DerivationPathFormat::Bip44Change);
    generate(seed_phrase, passphrase, count, Chain::Solana, DerivationPathFormat::Bip44Standard);
}

enum Chain {
    Bitcoin,
    Ethereum,
    Solana,
}

impl Chain {
    fn code(&self) -> u32 {
        match self {
            Self::Bitcoin => 0,
            Self::Ethereum => 60,
            Self::Solana => 501, // Solana's SLIP-44 code
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Bitcoin => "Bitcoin",
            Self::Ethereum => "Ethereum",
            Self::Solana => "Solana",
        }
    }
}

/// Represents different derivation path patterns for Solana wallets
enum DerivationPathFormat {
    /// Standard BIP44 derivation path for root (m/44'/chain'/x')
    Bip44Root,
    /// Standard BIP44 derivation with change path (m/44'/chain'/x'/0')
    Bip44Change,
    /// Standard BIP44 derivation without change (m/44'/chain'/x')
    Bip44Standard,
    /// Deprecated BIP44 derivation path (m/44'/chain'/x'/0/0)
    Bip44Deprecated,
}

impl DerivationPathFormat {
    /// Returns the path pattern string with a placeholder for the account index
    fn pattern(&self) -> &'static str {
        match self {
            Self::Bip44Root => "m/44'/{}'",
            Self::Bip44Change => "m/44'/{}'/{}'/0'",
            Self::Bip44Standard => "m/44'/{}'/{}'",
            Self::Bip44Deprecated => "m/44'/{}'/{}'/0/0",
        }
    }

    /// Returns a human-readable name for the derivation path type
    fn name(&self) -> &'static str {
        match self {
            Self::Bip44Root => "BIP44 Root",
            Self::Bip44Change => "BIP44 Change",
            Self::Bip44Standard => "BIP44 Standard",
            Self::Bip44Deprecated => "BIP44 Deprecated",
        }
    }
}

fn generate(seed_phrase: &str, passphrase: &str, count: usize, chain: Chain, derivation_path_type: DerivationPathFormat) {
    // Generate seed from mnemonic
    let seed = match generate_seed_from_mnemonic(seed_phrase, passphrase) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    // Derive and display wallet addresses
    println!("{} [{}]:", chain.name(), derivation_path_type.name());
    for index in 0..count {
        let path_str = derivation_path_type.pattern()
            .replacen("{}", &chain.code().to_string(), 1)
            .replacen("{}", &index.to_string(), 1);
        derive_and_display_addresses(&seed, &path_str, &chain);
    }
    println!("------------------------------------------------------------------");
}

// Generates a seed from a mnemonic phrase and optional passphrase
fn generate_seed_from_mnemonic(seed_phrase: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    // Parse the English mnemonic phrase
    let mnemonic = Mnemonic::parse_in(Language::English, seed_phrase)
        .map_err(|e| format!("Error parsing seed phrase: {}", e))?;

    // Generate the BIP39 seed from the mnemonic and optional passphrase
    Ok(mnemonic.to_seed(passphrase).to_vec())
}

// Derives and displays addresses for a given derivation path and chain
fn derive_and_display_addresses(seed: &[u8], path_str: &str, chain: &Chain) {
    match chain {
        Chain::Bitcoin => derive_bitcoin_address(seed, path_str),
        Chain::Ethereum => derive_ethereum_address(seed, path_str),
        Chain::Solana => derive_solana_address(seed, path_str),
    }
}

// Derives and displays Bitcoin address
fn derive_bitcoin_address(seed: &[u8], path_str: &str) {
    // Parse path for Bitcoin
    let btc_path: Bip32Path = match path_str.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Error parsing secp256k1 derivation path '{}': {}", path_str, e);
            return;
        }
    };

    match bip32::XPrv::derive_from_path(seed, &btc_path) {
        Ok(child_key) => {
            let public_key = *child_key.public_key().public_key();

            // Generate Bitcoin P2PKH Address
            let btc_address = generate_bitcoin_address(&public_key);
            println!("[{}] {}", path_str, btc_address);
        },
        Err(e) => {
            eprintln!("  Error deriving secp256k1 key (BTC): {}", e);
        }
    }
}

// Derives and displays Ethereum address
fn derive_ethereum_address(seed: &[u8], path_str: &str) {
    // Parse path for Ethereum
    let eth_path: Bip32Path = match path_str.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Error parsing secp256k1 derivation path '{}': {}", path_str, e);
            return;
        }
    };

    match bip32::XPrv::derive_from_path(seed, &eth_path) {
        Ok(child_key) => {
            let public_key = *child_key.public_key().public_key();

            // Generate Ethereum Address
            let eth_address = generate_ethereum_address(&public_key);
            println!("[{}] {}", path_str, eth_address);
        },
        Err(e) => {
            eprintln!("  Error deriving secp256k1 key (ETH): {}", e);
        }
    }
}

// Derives and displays Solana address
fn derive_solana_address(seed: &[u8], path_str: &str) {
    // Parse path for Solana
    let solana_path: Slip10Path = match path_str.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Error parsing Ed25519 derivation path '{}': {}", path_str, e);
            return;
        }
    };

    match derive_key_from_path(seed, Curve::Ed25519, &solana_path) {
        Ok(solana_key) => {
            let pk = &solana_key.public_key()[solana_key.public_key().len() - 32..];
            let solana_address = bs58::encode(pk).into_string();
            println!("[{}] {}", path_str, solana_address);
        },
        Err(e) => {
            eprintln!("  Error deriving Ed25519 key (Solana): {:?}", e);
        }
    }
}

// Generates a legacy Bitcoin P2PKH address.
fn generate_bitcoin_address(public_key: &VerifyingKey) -> String {
    // 1. Get compressed public key and hash it (SHA-256 -> RIPEMD-160)
    let pub_key_bytes = public_key.to_sec1_bytes();
    let sha256_hash = Sha256::digest(&pub_key_bytes);
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha256_hash);
    let pub_key_hash = ripemd_hasher.finalize();

    // 2. Add version byte (0x00 for mainnet)
    let mut address_data = vec![0x00];
    address_data.extend_from_slice(&pub_key_hash);

    // 3. Base58Check encode the result
    bs58::encode(address_data).with_check().into_string()
}

// Generates an Ethereum address with EIP-55 checksum.
fn generate_ethereum_address(public_key: &VerifyingKey) -> String {
    // 1. Get the uncompressed public key.
    let encoded_point = public_key.to_encoded_point(false);
    let uncompressed_bytes = &encoded_point.as_bytes()[1..];

    // 2. Hash it with Keccak-256
    let mut hasher = Keccak::v256();
    hasher.update(uncompressed_bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    // 3. Take the last 20 bytes
    let address_bytes = &output[12..];
    let address_hex = hex::encode(address_bytes);

    // 4. Apply EIP-55 checksum
    let mut hasher = Keccak::v256();
    hasher.update(address_hex.as_bytes());
    let mut checksum_hash = [0u8; 32];
    hasher.finalize(&mut checksum_hash);

    let checksum_address: String = address_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_digit(10) {
                c
            } else if checksum_hash[i / 2] >> (4 * (1 - i % 2)) & 0xF >= 8 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();

    format!("0x{}", checksum_address)
}

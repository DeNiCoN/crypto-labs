use ciphers::{Cipher, ColumnarTransposition};
use hex;
use rand::{self, rngs::StdRng, SeedableRng};
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use sha1::{Digest, Sha1};
use std::str;

fn main() {
    let message = "Шаблій Володимир Сергійович";
    let mut hasher = Sha1::new();
    hasher.update(message);
    let result = hasher.finalize();
    println!("Input message: {message}");
    let hex_hash = hex::encode(result);
    println!("Hashed message: {hex_hash}");
    let key = "algorithms";
    let cipher = ColumnarTransposition::new(key);

    println!();
    println!("Symetric key: {key}");
    let encrypted_hash = cipher.encipher(&hex_hash).unwrap();
    println!("Encrypted hashed message: {encrypted_hash}");

    let mut rng = StdRng::seed_from_u64(42);

    let bits = 256;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    println!();
    println!("{private_pem}");
    println!("{public_pem}");

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &key.as_bytes()[..])
        .expect("failed to encrypt");
    let enc_data_hex = hex::encode(&enc_data);
    println!("Encrypted symetric key: {enc_data_hex}");

    let received_message = "Шаблій Володимир Сергійович";
    println!();
    println!("Start of decryption");
    println!("Received message: {received_message}");
    println!("Received encrypted key: {enc_data_hex}");
    println!("Received encrypted hash: {encrypted_hash}");

    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");

    println!();
    let key = str::from_utf8(&dec_data).unwrap();
    println!("Decrypted symetric key: {key}",);

    let decrypted_hash = cipher.decipher(&encrypted_hash).unwrap();
    println!("Decrypted hashed message: {decrypted_hash}");

    let mut hasher = Sha1::new();
    hasher.update(received_message);
    let result = hasher.finalize();
    let hex_hash = hex::encode(result);
    println!("Hashed received message:  {hex_hash}");
}

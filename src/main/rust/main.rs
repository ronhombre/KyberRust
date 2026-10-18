#[cfg(feature = "executable")]
use core::convert::Infallible;
#[cfg(feature = "executable")]
use kyberrust::*;
#[cfg(feature = "executable")]
use rand::{TryCryptoRng, TryRng};

#[cfg(feature = "executable")]
struct ConstantRng(u8);

#[cfg(feature = "executable")]
impl TryRng for ConstantRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}

#[cfg(feature = "executable")]
impl TryCryptoRng for ConstantRng {}

#[cfg(feature = "executable")]
fn main() {
    let mut rng = ConstantRng(16u8);
    let key_pair = mlkem512::generate_kem_with_rng(&mut rng).unwrap();

    println!("Parameter: {}", key_pair.encapsulation_key.get_parameter().name);

    let mut encapsulation_key_bytes = vec![0u8; key_pair.encapsulation_key.byte_length()];
    key_pair
        .encapsulation_key
        .get_full_bytes(&mut encapsulation_key_bytes)
        .unwrap();
    println!("Encapsulation Key: {}", hex::encode(&encapsulation_key_bytes));

    let mut decapsulation_key_bytes = vec![0u8; key_pair.decapsulation_key.byte_length()];
    key_pair
        .decapsulation_key
        .get_full_bytes(&mut decapsulation_key_bytes)
        .unwrap();
    println!("Decapsulation Key: {}", hex::encode(&decapsulation_key_bytes));

    let mut plaintext = [2u8; 32];
    let mut randomness = [3u8; 32];
    let ciphertext = pke::to_cipher_text(&key_pair.encapsulation_key.key, &mut plaintext, &mut randomness);

    let mut ciphertext_bytes = vec![0u8; ciphertext.byte_length()];
    ciphertext.get_full_bytes(&mut ciphertext_bytes).unwrap();
    println!("Ciphertext: {}", hex::encode(&ciphertext_bytes));

    let secret_key = pke::from_cipher_text(&key_pair.decapsulation_key.key, &ciphertext);
    println!("Secret Key: {}", hex::encode(secret_key));

    plaintext.fill(2);

    let (secret_key_2, ciphertext_2) = kem::encapsulate_internal(&key_pair.encapsulation_key, &mut plaintext).unwrap();
    println!("Secret Key 2: {}", hex::encode(secret_key_2));

    let mut ciphertext_2_bytes = vec![0u8; ciphertext_2.byte_length()];
    ciphertext_2.get_full_bytes(&mut ciphertext_2_bytes).unwrap();
    println!("Ciphertext 2: {}", hex::encode(&ciphertext_2_bytes));

    let secret_key_3 = kem::decapsulate(&key_pair.decapsulation_key, &ciphertext_2);
    println!("Secret Key 3: {}", hex::encode(secret_key_3));
}

#[cfg(not(feature = "executable"))]
fn main() {}

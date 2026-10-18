use crate::{KyberDecapsulationKey, KyberEncapsulationKey, KyberCipherText, KyberError};
use crate::constants::SECRET_KEY_LENGTH;
use crate::pke::{from_cipher_text, to_cipher_text};

use keccakrust::{SHA3_256, SHA3_512, SHAKE_256};

use zeroize::Zeroize;

#[cfg(feature = "executable")]
pub fn encapsulate_internal<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    encapsulation_key: &KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>,
    plaintext: &mut [u8; SECRET_KEY_LENGTH]
) -> Result<([u8; SECRET_KEY_LENGTH], KyberCipherText<K, ETA1, ETA2, DU, DV>), KyberError> {
    _encapsulate_internal(encapsulation_key, plaintext)
}

#[cfg(not(feature = "executable"))]
fn encapsulate_internal<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    encapsulation_key: &KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>,
    plaintext: &mut [u8; SECRET_KEY_LENGTH]
) -> Result<([u8; SECRET_KEY_LENGTH], KyberCipherText<K, ETA1, ETA2, DU, DV>), KyberError> {
    _encapsulate_internal(encapsulation_key, plaintext)
}

fn _encapsulate_internal<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    encapsulation_key: &KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>,
    plaintext: &mut [u8; SECRET_KEY_LENGTH]
) -> Result<([u8; SECRET_KEY_LENGTH], KyberCipherText<K, ETA1, ETA2, DU, DV>), KyberError> {
    if plaintext.iter().fold(true, |acc, &x| acc & (x == 0)) {
        return Err(KyberError::RandomBitGeneration);
    }

    let mut key_hash_stream = SHA3_256::new_input_stream();
    key_hash_stream.write_bytes(encapsulation_key.key.key.as_flattened());
    key_hash_stream.write_bytes(&encapsulation_key.key.ntt_seed);
    let mut key_hash_stream = key_hash_stream.close();
    let mut key_hash = [0u8; 32];
    key_hash_stream.next_bytes(&mut key_hash);

    let mut shared_key_and_randomness_stream = SHA3_512::new_input_stream();
    shared_key_and_randomness_stream.write_bytes(plaintext);
    shared_key_and_randomness_stream.write_bytes(&key_hash);
    let mut shared_key_and_randomness_stream = shared_key_and_randomness_stream.close();
    let mut shared_secret_key = [0u8; SECRET_KEY_LENGTH];
    let mut randomness = [0u8; SECRET_KEY_LENGTH];

    shared_key_and_randomness_stream.next_bytes(&mut shared_secret_key);
    shared_key_and_randomness_stream.next_bytes(&mut randomness);

    let ciphertext = to_cipher_text(&encapsulation_key.key, plaintext, &mut randomness);

    Ok((shared_secret_key, ciphertext))
}

pub fn decapsulate<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    decapsulation_key: &KyberDecapsulationKey<K, ETA1, ETA2, DU, DV>,
    ciphertext: &KyberCipherText<K, ETA1, ETA2, DU, DV>
) -> [u8; SECRET_KEY_LENGTH] {
    let mut recovered_plaintext = from_cipher_text(&decapsulation_key.key, ciphertext);

    let mut key_buffer = [0u8; 32];
    let mut hash_buffer = [0u8; 32];

    let mut decaps_hash_stream = SHA3_512::new_input_stream();
    decaps_hash_stream.write_bytes(&recovered_plaintext);
    decaps_hash_stream.write_bytes(&decapsulation_key.hash);
    let mut decaps_hash_stream = decaps_hash_stream.close();

    decaps_hash_stream.next_bytes(&mut key_buffer);
    decaps_hash_stream.next_bytes(&mut hash_buffer);

    let mut regenerated_ciphertext = to_cipher_text(
        &decapsulation_key.encryption_key,
        &mut recovered_plaintext, //Gets zeroed in the function TODO: Add tests for this assumption
        &mut hash_buffer //Gets zeroed in the function TODO: Add tests for this assumption
    );

    let coefficients = ciphertext.encoded_coefficients.as_flattened().as_flattened();
    let terms = ciphertext.encoded_terms.as_flattened();

    let mut hash_stream = SHAKE_256::new_input_stream();
    hash_stream.write_bytes(&decapsulation_key.random_seed);
    hash_stream.write_bytes(coefficients);
    hash_stream.write_bytes(terms);
    let mut hash_stream = hash_stream.close();

    hash_stream.next_bytes(&mut hash_buffer);

    let regenerated_coefficients = regenerated_ciphertext.encoded_coefficients.as_flattened().as_flattened();
    let regenerated_terms = regenerated_ciphertext.encoded_terms.as_flattened();

    let mut fail = 0;
    for i in 0..regenerated_coefficients.len() {
        fail |= regenerated_coefficients[i] ^ coefficients[i];
    }
    for i in 0..regenerated_terms.len() {
        fail |= regenerated_terms[i] ^ terms[i];
    }

    regenerated_ciphertext.zeroize();

    let success = (fail.wrapping_sub(1) >> 7).wrapping_sub(1);

    for i in 0..SECRET_KEY_LENGTH {
        let correct_byte = key_buffer[i];
        let rejected_byte = hash_buffer[i];

        key_buffer[i] ^= success & (correct_byte ^ rejected_byte);
    }

    hash_buffer.zeroize();

    key_buffer
}
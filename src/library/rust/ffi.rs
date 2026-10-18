/*
 * Copyright 2026 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *        
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::borrowed::{CipherTextRef, DecapsulationKeyRef, EncryptionKeyRef};
use crate::constants::{ENCODE_SIZE, N_BYTES, SECRET_KEY_LENGTH};
use crate::{FullBytes, KyberError, KyberParameter, generator, kem, kybermath, pke};

use keccakrust::SHA3_256;

use zeroize::Zeroize;

fn output_buffer(output: &mut [u8], size: usize) -> Result<&mut [u8], KyberError> {
    output.get_mut(..size).ok_or(KyberError::BufferTooSmall)
}

fn key_length(bytes: &[u8], expected: usize, known_lengths: &[usize]) -> Result<(), KyberError> {
    if bytes.len() == expected {
        Ok(())
    } else if known_lengths.contains(&bytes.len()) {
        Err(KyberError::MismatchingKyberVariant)
    } else {
        Err(KyberError::InvalidKyberKey)
    }
}

fn encryption_key<const K: usize>(bytes: &[u8]) -> Result<EncryptionKeyRef<'_>, KyberError> {
    key_length(bytes, ENCODE_SIZE * K + N_BYTES, &[800, 1184, 1568])?;

    let (key, ntt_seed) = bytes.split_at(ENCODE_SIZE * K);

    if !kybermath::fast_modulo_check(key) {
        return Err(KyberError::InvalidKyberKey);
    }

    Ok(EncryptionKeyRef { key, ntt_seed })
}

fn ciphertext<const K: usize, const DU: usize, const DV: usize>(
    bytes: &[u8],
) -> Result<CipherTextRef<'_>, KyberError> {
    key_length(bytes, N_BYTES * (DU * K + DV), &[768, 1088, 1568])?;

    let (coefficients, terms) = bytes.split_at(N_BYTES * DU * K);

    Ok(CipherTextRef {
        coefficients,
        terms,
    })
}

pub fn generate<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    random_seed: &[u8; N_BYTES],
    pke_seed: &mut [u8; N_BYTES],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(
        output,
        KyberParameter::<K, ETA1, ETA2, DU, DV>::decapsulation_key_length(),
    )?;
    let result = generator::generate_kem_internal(parameter, *random_seed, *pke_seed);

    pke_seed.zeroize();

    result?.decapsulation_key.get_full_bytes(output)?;

    Ok(())
}

pub fn generate_pke<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    pke_seed: &mut [u8; N_BYTES],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(output, 2 * ENCODE_SIZE * K + N_BYTES)?;
    let result = generator::generate_pke(parameter, *pke_seed);

    pke_seed.zeroize();

    let pair = result?;
    let (dk, ek) = output.split_at_mut(ENCODE_SIZE * K);

    pair.decryption_key.get_full_bytes(dk)?;
    pair.encryption_key.get_full_bytes(ek)?;

    Ok(())
}

pub fn encapsulate<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: &[u8],
    plaintext: &mut [u8; N_BYTES],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(
        output,
        SECRET_KEY_LENGTH + KyberParameter::<K, ETA1, ETA2, DU, DV>::ciphertext_length(),
    )?;
    let key = encryption_key::<K>(key)?;
    let (mut secret, ciphertext) = kem::encapsulate_borrowed(parameter, key, plaintext)?;

    output[..SECRET_KEY_LENGTH].copy_from_slice(&secret);

    secret.zeroize();

    ciphertext.get_full_bytes(&mut output[SECRET_KEY_LENGTH..])?;

    Ok(())
}

pub fn decapsulate<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: &[u8],
    ciphertext_bytes: &[u8],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(output, SECRET_KEY_LENGTH)?;
    key_length(key, 2 * ENCODE_SIZE * K + 3 * N_BYTES, &[1632, 2400, 3168])?;
    let (dk, rest) = key.split_at(ENCODE_SIZE * K);

    if !kybermath::fast_modulo_check(dk) {
        return Err(KyberError::InvalidKyberKey);
    }

    let (ek, rest) = rest.split_at(ENCODE_SIZE * K + N_BYTES);
    let encryption_key = encryption_key::<K>(ek)?;
    let (hash, random_seed) = rest.split_at(N_BYTES);
    let mut expected_hash = [0u8; N_BYTES];
    SHA3_256::digest(ek).next_bytes(&mut expected_hash);

    if hash != expected_hash {
        return Err(KyberError::InvalidKyberKey);
    }

    let ciphertext = ciphertext::<K, DU, DV>(ciphertext_bytes)?;
    let mut secret = kem::decapsulate_borrowed(
        parameter,
        DecapsulationKeyRef {
            key: dk,
            encryption_key,
            hash,
            random_seed,
        },
        ciphertext,
    );

    output.copy_from_slice(&secret);

    secret.zeroize();

    Ok(())
}

pub fn encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: &[u8],
    plaintext: &mut [u8; N_BYTES],
    randomness: &mut [u8; N_BYTES],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(
        output,
        KyberParameter::<K, ETA1, ETA2, DU, DV>::ciphertext_length(),
    )?;
    let key = encryption_key::<K>(key)?;

    pke::to_cipher_text_borrowed(parameter, key, plaintext, randomness).get_full_bytes(output)?;

    Ok(())
}

pub fn decrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    _parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: &[u8],
    ciphertext_bytes: &[u8],
    output: &mut [u8],
) -> Result<(), KyberError> {
    let output = output_buffer(output, N_BYTES)?;
    key_length(key, ENCODE_SIZE * K, &[768, 1152, 1536])?;

    if !kybermath::fast_modulo_check(key) {
        return Err(KyberError::InvalidKyberKey);
    }

    let ciphertext = ciphertext::<K, DU, DV>(ciphertext_bytes)?;
    let mut plaintext = pke::from_cipher_text_borrowed::<K, ETA1, ETA2, DU, DV>(key, ciphertext);

    output.copy_from_slice(&plaintext);

    plaintext.zeroize();

    Ok(())
}

#![allow(clippy::needless_range_loop)] //Doesn't actually make sense here

use crate::{Kyber, FullBytes, KyberEncryptionKey, KyberDecryptionKey, KyberCipherText};
use crate::constants::*;
use crate::kybermath;

use keccakrust::{SHAKE_128, SHAKE_256};

use zeroize::Zeroize;

pub fn to_cipher_text<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    encryption_key: &KyberEncryptionKey<K, ETA1, ETA2, DU, DV>,
    plaintext: &mut [u8; SECRET_KEY_LENGTH],
    randomness: &mut [u8; SECRET_KEY_LENGTH]
) -> KyberCipherText<K, ETA1, ETA2, DU, DV> {
    let mut constant_term = [0i32; N];
    let mut coefficients = [[0i32; N]; K];

    let mut temp_buffer = [0i32; N];
    let mut randomness_element = [0i32; N];

    for i in 0..K {
        kybermath::fast_byte_decode_into(
            &mut temp_buffer,
            encryption_key.key.as_flattened(),
            12,
            i * ENCODE_SIZE,
            ENCODE_SIZE,
            false
        );
        kybermath::vector_to_mont_vector(&mut temp_buffer);

        let mut prf_stream = SHAKE_256::new_input_stream();
        prf_stream.write_bytes(randomness);
        prf_stream.write_byte(i as u8);
        let mut prf_stream = prf_stream.close();
        let mut prf = [[0u8; QUART_N]; ETA1];
        let prf = prf.as_flattened_mut();
        prf_stream.next_bytes(prf);
        kybermath::sample_poly_cbd_into(&mut randomness_element, ETA1, prf);
        kybermath::ntt(&mut randomness_element);

        kybermath::multiply_ntts_into(&mut constant_term, &mut randomness_element, &mut temp_buffer, 0);

        for j in 0..K {
            let mut xof_stream = SHAKE_128::new_input_stream();
            xof_stream.write_bytes(&encryption_key.ntt_seed);
            xof_stream.write_byte(j as u8);
            xof_stream.write_byte(i as u8);
            let mut xof_stream = xof_stream.close();
            kybermath::sample_ntt_into(&mut temp_buffer, &mut xof_stream);
            kybermath::multiply_ntts_into(&mut coefficients[j], &mut temp_buffer, &mut randomness_element, 0)
        }

        randomness_element.zeroize();
    }

    for i in 0..K {
        for k in 0..N {
            coefficients[i][k] = kybermath::barrett_reduce(coefficients[i][k]);
        }
    }

    kybermath::ntt_inv(&mut constant_term);

    let mut prf_stream = SHAKE_256::new_input_stream();
    prf_stream.write_bytes(randomness);
    prf_stream.write_byte((K * 2) as u8);
    let mut prf_stream = prf_stream.close();
    let mut prf = [[0u8; QUART_N]; ETA2];
    let prf = prf.as_flattened_mut();
    prf_stream.next_bytes(prf);
    kybermath::sample_poly_cbd_into(&mut temp_buffer, ETA2, prf);

    kybermath::vector_to_vector_add(&mut constant_term, &temp_buffer);

    kybermath::expand_and_add_muse_into(plaintext, &mut constant_term);
    plaintext.zeroize();

    let mut encoded_terms = [[0u8; N_BYTES]; DV];
    let encoded_terms_flat = encoded_terms.as_flattened_mut();
    kybermath::compress_and_encode_into(encoded_terms_flat, 0, &constant_term, DV);

    let mut encoded_coefficients = [[[0u8; N_BYTES]; DU]; K];
    let encoded_coefficients_flat = encoded_coefficients.as_flattened_mut().as_flattened_mut();
    for i in 0..K {
        kybermath::ntt_inv(&mut coefficients[i]);

        let mut prf_stream = SHAKE_256::new_input_stream();
        prf_stream.write_bytes(randomness);
        prf_stream.write_byte((i + K) as u8);
        let mut prf_stream = prf_stream.close();
        let mut prf = [[0u8; QUART_N]; ETA2];
        let prf = prf.as_flattened_mut();
        prf_stream.next_bytes(prf);
        kybermath::sample_poly_cbd_into(&mut temp_buffer, ETA2, prf);

        kybermath::vector_to_vector_add(&mut coefficients[i], &temp_buffer);

        kybermath::compress_and_encode_into(
            encoded_coefficients_flat,
            i * N_BYTES * DU,
            &coefficients[i],
            DU
        )
    }

    temp_buffer.zeroize();
    randomness.zeroize();

    KyberCipherText {
        parameter: encryption_key.get_parameter(),
        encoded_coefficients,
        encoded_terms
    }
}

pub fn from_cipher_text<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    decryption_key: &KyberDecryptionKey<K, ETA1, ETA2, DU, DV>,
    ciphertext: &KyberCipherText<K, ETA1, ETA2, DU, DV>
) -> [u8; SECRET_KEY_LENGTH] {
    let mut coefficients = [0i32; N];

    let mut secret_vector = [[0i32; N]; K];
    let secret_vector = secret_vector.as_flattened_mut();
    kybermath::fast_byte_decode_into(
        secret_vector,
        decryption_key.key.as_flattened(),
        12,
        0,
        decryption_key.byte_length(),
        false
    );
    kybermath::vector_to_mont_vector(secret_vector);

    let mut constant_terms = [0i32; N];
    kybermath::fast_byte_decode_into(
        &mut constant_terms,
        ciphertext.encoded_terms.as_flattened(),
        DV,
        0,
        N_BYTES * DV,
        true
    );
    kybermath::vector_to_mont_vector(&mut constant_terms);

    let mut subtraction = [0i32; N];
    for i in 0..K {
        kybermath::fast_byte_decode_into(
            &mut coefficients,
            ciphertext.encoded_coefficients[i].as_flattened(),
            DU,
            0,
            N_BYTES * DU,
            true
        );
        kybermath::vector_to_mont_vector(&mut coefficients);
        kybermath::ntt(&mut coefficients);

        kybermath::multiply_ntts_into(&mut subtraction, secret_vector, &mut coefficients, i * N)
    }

    kybermath::ntt_inv(&mut subtraction);

    for i in 0..N {
        constant_terms[i] -= subtraction[i];
    }

    let mut result = [0u8; SECRET_KEY_LENGTH];
    kybermath::compress_constants(&mut result, 0, &constant_terms);

    result
}
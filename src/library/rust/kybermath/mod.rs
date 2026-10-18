#![allow(clippy::needless_range_loop)] //Doesn't actually make sense here

use crate::constants::*;

use keccakrust::HashOutputStream;

#[inline]
fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

pub fn fast_byte_decode_into(
    result: &mut [i32],
    bytes: &[u8],
    bit_size: usize,
    offset: usize,
    length: usize ,
    decompress: bool
) {
    let last_index = offset + length - 1;
    let mut byte_index = offset;
    let mut usable_bits = 8;
    let mut current_byte = bytes[byte_index] as i32;

    for i in 0..result.len() {
        let mut accumulator = 0;
        let mut ingested_bits = 0;

        while ingested_bits < bit_size {
            let can_ingest = min(usable_bits, bit_size - ingested_bits);
            let mask = 0xFF >> (8 - can_ingest);
            accumulator |= (current_byte & mask) << ingested_bits;
            current_byte >>= can_ingest;
            usable_bits -= can_ingest;
            ingested_bits += can_ingest;
            if usable_bits == 0 && byte_index < last_index {
                byte_index += 1;
                current_byte = bytes[byte_index] as i32;
                usable_bits = 8;
            }
        }
        result[i] = if decompress {
            ((Q * accumulator) + (1 << (bit_size - 1))) >> bit_size
        } else {
            accumulator
        };
    }
}

#[inline]
pub fn fast_modulo_check(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < (bytes.len() - 2) {
        let b0 = bytes[i] as i32;
        let b1 = bytes[i + 1] as i32;
        let b2 = bytes[i + 2] as i32;

        let d1 = b0 | ((b1 & 0x0F) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);

        if !is_modulo_of_q(d1) || !is_modulo_of_q(d2) {
            return false;
        }

        i += 3;
    }

    true
}

pub fn byte_encode_into(output: &mut [u8], dest_index: usize, vector: &[i32; 256]) {
    let mut dest_index = dest_index;
    let mut i = 0;

    while i < vector.len() {
        let v0 = barrett_reduce(montgomery_reduce(vector[i]));
        let v1 = barrett_reduce(montgomery_reduce(vector[i + 1]));

        output[dest_index] = (v0 & 0xFF) as u8;
        dest_index += 1;
        output[dest_index] = ((v0 >> 8 & 0x0F) | ((v1 & 0x0F) << 4)) as u8;
        dest_index += 1;
        output[dest_index] = (v1 >> 4 & 0xFF) as u8;
        dest_index += 1;

        i += 2
    }
}

pub fn compress_and_encode_into(
    output: &mut [u8],
    dest_index: usize,
    vector: &[i32; 256],
    bit_size: usize
) {
    let mut dest_index = dest_index;
    let mask = 1 << bit_size;
    let mut bit_index = 0;
    let mut temp = 0;
    for i in 0..vector.len() {
        let value = ((mask * montgomery_reduce(vector[i])) + Q_HALF) / Q;

        for j in 0..bit_size {
            temp |= ((value >> j) & 1) << bit_index;
            bit_index += 1;
            if bit_index == 8 {
                output[dest_index] = temp as u8;
                dest_index += 1;
                bit_index = 0;
                temp = 0;
            }
        }
    }
}

pub fn compress_constants(output: &mut [u8], dest_index: usize, vector: &[i32; 256]) {
    let mut dest_index = dest_index;
    let mut i = 0;
    while i < vector.len() {
        let mut temp = 0;
        for j in 0..8 {
            let x = montgomery_reduce(vector[i + j]) * 0b10;
            let value = (x + Q_HALF) / Q;
            temp |= (value & 1) << j
        }
        output[dest_index] = temp as u8;
        dest_index += 1;

        i += 8
    }
}

pub fn expand_and_add_muse_into(bytes: &[u8], vector: &mut [i32; 256]) {
    let decompress_constant = to_montgomery_form(Q_HALF + 1);

    for i in 0..bytes.len() {
        let byte = bytes[i] as i32;
        for j in 0..8 {
            vector[(i * 8) + j] += ((byte >> j) & 1) * decompress_constant;
        }
    }
}

pub fn sample_ntt_into(ntt_coefficients: &mut [i32; 256], byte_stream: &mut HashOutputStream) {
    let mut buffer = [0u8; 3];

    let mut j = 0usize;
    while j < N {
        byte_stream.next_bytes(&mut buffer);

        let d1 = ((buffer[0] as i32 & 0xFF)      | ((buffer[1] as i32) << 8)) & 0xFFF;
        let d2 = ((buffer[1] as i32 & 0xFF) >> 4 | ((buffer[2] as i32) << 4)) & 0xFFF;

        if d1 < Q {
            ntt_coefficients[j] = to_montgomery_form(d1);
            j += 1
        }
        if d2 < Q && j < N {
            ntt_coefficients[j] = to_montgomery_form(d2);
            j += 1
        }
    }
}

pub fn sample_poly_cbd_into(constants: &mut [i32; N], eta: usize, bytes: &[u8]) {
    for i in 0..N {
        let offset = 2 * i * eta;
        let mut value = 0;
        for j in 0..eta {
            let mut index: usize = offset + j;
            value += (bytes[index >> 3] as i32 >> (index & 0b111)) & 1;
            index += eta;
            value -= (bytes[index >> 3] as i32 >> (index & 0b111)) & 1;
        }
        constants[i] = to_montgomery_form(value);
    }
}

pub fn ntt(polynomials: &mut [i32; 256]) {
    let mut k = 1;
    let mut len: usize = N >> 1;

    while len >= 2 {
        let mut start: usize = 0;
        while start < N {
            let zeta = PRECOMPUTED_ZETAS_TABLE[k];
            for j in start..(start + len) {
                let poly_j = polynomials[j];
                let poly_jlen = product_of(zeta, polynomials[j + len]);
                polynomials[j + len] = poly_j - poly_jlen;
                polynomials[j] =       poly_j + poly_jlen;
            }

            k += 1;
            start += len << 1;
        }

        len >>= 1;
    }
}

pub fn ntt_inv(ntt_polynomials: &mut [i32; 256]) {
    let mut k = (N >> 1) - 1;
    let mut len: usize = 2;

    while len <= (N >> 1) {
        let mut start: usize = 0;
        while start < N {
            let zeta = PRECOMPUTED_ZETAS_TABLE[k];
            for j in start..(start + len) {
                let poly_j = ntt_polynomials[j];
                let poly_jlen = ntt_polynomials[j + len];
                ntt_polynomials[j] =       poly_jlen + poly_j;
                ntt_polynomials[j + len] = product_of(zeta, poly_jlen - poly_j);
            }

            k -= 1;
            start += len << 1;
        }

        len <<= 1;
    }

    for i in 0..N {
        ntt_polynomials[i] = product_of(ntt_polynomials[i], 512); // toMontgomeryForm(3303) = 512
    }
}

#[inline]
pub fn product_of(a: i32, b: i32) -> i32 {
    montgomery_reduce(a * b)
}

pub fn multiply_ntts_into(dest: &mut [i32; 256], ntt1: &mut [i32], ntt2: &mut [i32], offset: usize) {
    for i in 0..(N >> 1) {
        let a = i << 1;
        let b = a + 1;

        let a0 = ntt1[a + offset];
        let a1 = ntt1[b + offset];
        let b0 = ntt2[a];
        let b1 = ntt2[b];
        let gamma = PRECOMPUTED_GAMMAS_TABLE[i];

        let x = product_of(a0, b0);
        let y = product_of(a1, b1);

        dest[a] += x + product_of(y, gamma);
        dest[b] += product_of(a0 + a1, b0 + b1) - x - y;
    }
}

#[inline]
pub fn vector_to_vector_add(v1: &mut [i32; 256], v2: &[i32; 256]) {
    for i in 0..v1.len() {
        v1[i] += v2[i];
    }
}

#[inline]
pub fn vector_to_mont_vector(vector: &mut [i32]) {
    for i in 0..vector.len() {
        vector[i] = barrett_reduce(to_montgomery_form(vector[i]));
    }
}

#[inline]
pub fn barrett_reduce(n: i32) -> i32 {
    let q = (n * BARRETT_APPROX) >> 26;
    let mut result = n - (q * Q);

    let is_q = (result ^ Q).wrapping_sub(1); // Underflows to 0xFFFFFFFF if result == Q
    let mask = is_q >> 31;
    result -= Q & mask;

    result
}

#[inline]
pub fn is_modulo_of_q(n: i32) -> bool {
    ((n * BARRETT_APPROX) >> 26) == 0 && n >= 0
}

#[inline]
pub fn montgomery_reduce(t: i32) -> i32 {
    let m = t.wrapping_mul(Q_INV) & 0xFFFF;

    (t + (m * Q)) >> 16
}

#[inline]
pub fn to_montgomery_form(a: i32) -> i32 {
    montgomery_reduce(a * MONT_R2)
}
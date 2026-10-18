#![no_std]

use keccakrust::SHA3_256;
use rand::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::constants::{N_BYTES, SECRET_KEY_LENGTH};
use crate::kem::encapsulate_internal;

#[cfg(all(not(debug_assertions), feature = "panic_handler"))]
use core::panic::PanicInfo;

pub mod constants;
mod kybermath;

mod generator;
mod borrowed;

#[cfg(feature = "ffi")]
pub mod ffi;

pub mod mlkem512;
pub mod mlkem768;
pub mod mlkem1024;

#[cfg(feature = "executable")]
pub mod pke;
#[cfg(not(feature = "executable"))]
mod pke;

#[cfg(feature = "executable")]
pub mod kem;
#[cfg(not(feature = "executable"))]
mod kem;

type MLKEMParameter<const K: usize, const ETA1: usize, const ETA2: usize, const DU: usize, const DV: usize> = KyberParameter<K, ETA1, ETA2, DU, DV>;

pub const ML_KEM_512: MLKEMParameter<2, 3, 2, 10, 4> = KyberParameter { name: "ML_KEM_512" };
pub const ML_KEM_768: MLKEMParameter<3, 2, 2, 10, 4> = KyberParameter { name: "ML_KEM_768" };
pub const ML_KEM_1024: MLKEMParameter<4, 2, 2, 11, 5> = KyberParameter { name: "ML_KEM_1024" };

#[derive(PartialEq, Eq, Copy)]
pub struct KyberParameter<const K: usize, const ETA1: usize, const ETA2: usize, const DU: usize, const DV: usize> {
    pub name: &'static str,
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberParameter<K, ETA1, ETA2, DU, DV> {
    pub fn ciphertext_length() -> usize {
        constants::N_BYTES * ((DU * K) + DV)
    }

    pub fn encryption_key_length() -> usize {
        Self::decryption_key_length() + constants::N_BYTES
    }

    pub fn decryption_key_length() -> usize {
        constants::ENCODE_SIZE * K
    }

    pub fn encapsulation_key_length() -> usize {
        Self::encryption_key_length()
    }

    pub fn decapsulation_key_length() -> usize {
        Self::encapsulation_key_length() + Self::decryption_key_length() + (2 * constants::N_BYTES)
    }

    pub const fn k(&self) -> usize { K }
    pub const fn eta1(&self) -> usize { ETA1 }
    pub const fn eta2(&self) -> usize { ETA2 }
    pub const fn du(&self) -> usize { DU }
    pub const fn dv(&self) -> usize { DV }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberParameter<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self { *self }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> ZeroizeOnDrop for KyberParameter<K, ETA1, ETA2, DU, DV> {}

pub trait Kyber<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV>;
}

pub trait FullBytes {
    fn byte_length(&self) -> usize;
    fn get_full_bytes(&self, destination: &mut [u8]) -> Result<usize, KyberError>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KyberError {
    InvalidKyberKey,
    RandomBitGeneration,
    UnsupportedKyberVariant,
    BufferTooSmall,
    MismatchingKyberVariant
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberCipherText<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    encoded_coefficients: [[[u8; constants::N_BYTES]; DU]; K],
    encoded_terms: [[u8; constants::N_BYTES]; DV]
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberCipherText<K, ETA1, ETA2, DU, DV> {
    pub fn decapsulate(&self, decapsulation_key: &KyberDecapsulationKey<K, ETA1, ETA2, DU, DV>) -> [u8; SECRET_KEY_LENGTH] {
        kem::decapsulate(decapsulation_key, self)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberCipherText<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberCipherText {
            parameter: self.parameter,
            encoded_coefficients: self.encoded_coefficients,
            encoded_terms: self.encoded_terms
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Kyber<K, ETA1, ETA2, DU, DV> for KyberCipherText<K, ETA1, ETA2, DU, DV> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV> {
        self.parameter
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> FullBytes for KyberCipherText<K, ETA1, ETA2, DU, DV> {
    fn byte_length(&self) -> usize {
        KyberParameter::<K, ETA1, ETA2, DU, DV>::ciphertext_length()
    }

    fn get_full_bytes(&self, destination: &mut [u8]) -> Result<usize, KyberError> {
        let total_len = self.byte_length();
        if destination.len() < total_len {
            return Err(KyberError::BufferTooSmall);
        }

        let u_bytes = self.encoded_coefficients.as_flattened().as_flattened();
        let v_bytes = self.encoded_terms.as_flattened();

        destination[..u_bytes.len()].copy_from_slice(u_bytes);
        destination[u_bytes.len()..total_len].copy_from_slice(v_bytes);
        Ok(total_len)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberCipherText<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.encoded_coefficients.zeroize();
        self.encoded_terms.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberEncryptionKey<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: [[u8; constants::ENCODE_SIZE]; K],
    ntt_seed: [u8; constants::N_BYTES]
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberEncryptionKey<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(
        parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
        key_slice: &[u8],
        seed_slice: &[u8],
    ) -> Result<Self, KyberError> {
        if key_slice.len() != KyberParameter::<K, ETA1, ETA2, DU, DV>::decryption_key_length()
            || seed_slice.len() != constants::N_BYTES
            || !kybermath::fast_modulo_check(key_slice)
        {
            return Err(KyberError::InvalidKyberKey);
        }

        let mut key = [[0u8; constants::ENCODE_SIZE]; K];
        key.as_flattened_mut().copy_from_slice(key_slice);

        let mut ntt_seed = [0u8; constants::N_BYTES];
        ntt_seed.copy_from_slice(seed_slice);

        Ok(Self {
            parameter,
            key,
            ntt_seed,
        })
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberEncryptionKey<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberEncryptionKey {
            parameter: self.parameter,
            key: self.key,
            ntt_seed: self.ntt_seed
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Kyber<K, ETA1, ETA2, DU, DV> for KyberEncryptionKey<K, ETA1, ETA2, DU, DV> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV> {
        self.parameter
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> FullBytes for KyberEncryptionKey<K, ETA1, ETA2, DU, DV> {
    fn byte_length(&self) -> usize {
        KyberParameter::<K, ETA1, ETA2, DU, DV>::encryption_key_length()
    }

    fn get_full_bytes(&self, destination: &mut [u8]) -> Result<usize, KyberError> {
        let total_len = self.byte_length();
        if destination.len() < total_len {
            return Err(KyberError::BufferTooSmall);
        }

        let key_bytes = self.key.as_flattened();
        destination[..key_bytes.len()].copy_from_slice(key_bytes);
        destination[key_bytes.len()..total_len].copy_from_slice(&self.ntt_seed);
        Ok(total_len)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberEncryptionKey<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.ntt_seed.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberDecryptionKey<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    key: [[u8; constants::ENCODE_SIZE]; K]
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberDecryptionKey<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(
        parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
        key_slice: &[u8],
    ) -> Result<Self, KyberError> {
        if key_slice.len() != KyberParameter::<K, ETA1, ETA2, DU, DV>::decryption_key_length()
            || !kybermath::fast_modulo_check(key_slice)
        {
            return Err(KyberError::InvalidKyberKey);
        }

        let mut key = [[0u8; constants::ENCODE_SIZE]; K];
        key.as_flattened_mut().copy_from_slice(key_slice);

        Ok(Self { parameter, key })
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberDecryptionKey<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberDecryptionKey {
            parameter: self.parameter,
            key: self.key
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Kyber<K, ETA1, ETA2, DU, DV> for KyberDecryptionKey<K, ETA1, ETA2, DU, DV> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV> {
        self.parameter
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> FullBytes for KyberDecryptionKey<K, ETA1, ETA2, DU, DV> {
    fn byte_length(&self) -> usize {
        KyberParameter::<K, ETA1, ETA2, DU, DV>::decryption_key_length()
    }

    fn get_full_bytes(&self, destination: &mut [u8]) -> Result<usize, KyberError> {
        let bytes = self.byte_length();
        if destination.len() < bytes {
            return Err(KyberError::BufferTooSmall);
        }
        destination[..bytes].copy_from_slice(self.key.as_flattened());
        Ok(bytes)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberDecryptionKey<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberPKEKeyPair<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    pub encryption_key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>,
    pub decryption_key: KyberDecryptionKey<K, ETA1, ETA2, DU, DV>
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberPKEKeyPair<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(encryption_key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>, decryption_key: KyberDecryptionKey<K, ETA1, ETA2, DU, DV>) -> KyberPKEKeyPair<K, ETA1, ETA2, DU, DV> {
        KyberPKEKeyPair {
            encryption_key,
            decryption_key
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberPKEKeyPair<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberPKEKeyPair {
            encryption_key: self.encryption_key.clone(),
            decryption_key: self.decryption_key.clone()
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberPKEKeyPair<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.encryption_key.zeroize();
        self.decryption_key.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberEncapsulationKey<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    pub key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberEncapsulationKey<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>) -> Result<KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>, KyberError> {
        Ok(KyberEncapsulationKey {
            key
        })
    }

    pub fn encapsulate<R: TryCryptoRng + ?Sized>(&self, rng: &mut R) -> Result<([u8; SECRET_KEY_LENGTH], KyberCipherText<K, ETA1, ETA2, DU, DV>), KyberError> {
        let mut plaintext = [0u8; N_BYTES];

        rng.try_fill_bytes(&mut plaintext).map_err(|_| KyberError::RandomBitGeneration)?;

        encapsulate_internal(self, &mut plaintext)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberEncapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberEncapsulationKey {
            key: self.key.clone()
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Kyber<K, ETA1, ETA2, DU, DV> for KyberEncapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV> {
        self.key.get_parameter()
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> FullBytes for KyberEncapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn byte_length(&self) -> usize {
        self.key.byte_length()
    }

    fn get_full_bytes(&self, out: &mut [u8]) -> Result<usize, KyberError> {
        self.key.get_full_bytes(out)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberEncapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberDecapsulationKey<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    pub key: KyberDecryptionKey<K, ETA1, ETA2, DU, DV>,
    pub encryption_key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>,
    hash: [u8; constants::N_BYTES],
    random_seed: [u8; constants::N_BYTES]
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberDecapsulationKey<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(
        key: KyberDecryptionKey<K, ETA1, ETA2, DU, DV>,
        encryption_key: KyberEncryptionKey<K, ETA1, ETA2, DU, DV>,
        hash_slice: &[u8],
        random_seed_slice: &[u8],
    ) -> Result<Self, KyberError> {
        if hash_slice.len() != constants::N_BYTES || random_seed_slice.len() != constants::N_BYTES {
            return Err(KyberError::InvalidKyberKey);
        }

        let mut ek_hash_stream = SHA3_256::new_input_stream();
        ek_hash_stream.write_bytes(encryption_key.key.as_flattened());
        ek_hash_stream.write_bytes(&encryption_key.ntt_seed);
        let mut ek_hash_stream = ek_hash_stream.close();

        let mut ek_hash = [0u8; 32];
        ek_hash_stream.next_bytes(&mut ek_hash);

        if hash_slice != ek_hash {
            return Err(KyberError::InvalidKyberKey);
        }

        let mut hash = [0u8; constants::N_BYTES];
        hash.copy_from_slice(hash_slice);

        let mut random_seed = [0u8; constants::N_BYTES];
        random_seed.copy_from_slice(random_seed_slice);

        Ok(Self {
            key,
            encryption_key,
            hash,
            random_seed,
        })
    }

    pub fn decapsulate(&self, ciphertext: &KyberCipherText<K, ETA1, ETA2, DU, DV>) -> [u8; SECRET_KEY_LENGTH] {
        kem::decapsulate(self, ciphertext)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberDecapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberDecapsulationKey {
            key: self.key.clone(),
            encryption_key: self.encryption_key.clone(),
            hash: self.hash,
            random_seed: self.random_seed
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Kyber<K, ETA1, ETA2, DU, DV> for KyberDecapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn get_parameter(&self) -> KyberParameter<K, ETA1, ETA2, DU, DV> {
        self.key.get_parameter()
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> FullBytes for KyberDecapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn byte_length(&self) -> usize {
        KyberParameter::<K, ETA1, ETA2, DU, DV>::decapsulation_key_length()
    }

    fn get_full_bytes(&self, destination: &mut [u8]) -> Result<usize, KyberError> {
        let total_len = self.byte_length();
        if destination.len() < total_len {
            return Err(KyberError::BufferTooSmall);
        }

        let mut offset = 0;
        offset += self.key.get_full_bytes(&mut destination[offset..])?;
        offset += self.encryption_key.get_full_bytes(&mut destination[offset..])?;

        destination[offset..offset + constants::N_BYTES].copy_from_slice(&self.hash);
        offset += constants::N_BYTES;

        destination[offset..offset + constants::N_BYTES].copy_from_slice(&self.random_seed);
        offset += constants::N_BYTES;

        Ok(offset)
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberDecapsulationKey<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.encryption_key.zeroize();
        self.hash.zeroize();
        self.random_seed.zeroize();
    }
}

#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct KyberKEMKeyPair<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> {
    pub encapsulation_key: KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>,
    pub decapsulation_key: KyberDecapsulationKey<K, ETA1, ETA2, DU, DV>
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> KyberKEMKeyPair<K, ETA1, ETA2, DU, DV> {
    pub(crate) fn new(encapsulation_key: KyberEncapsulationKey<K, ETA1, ETA2, DU, DV>, decapsulation_key: KyberDecapsulationKey<K, ETA1, ETA2, DU, DV>) -> KyberKEMKeyPair<K, ETA1, ETA2, DU, DV> {
        KyberKEMKeyPair {
            encapsulation_key,
            decapsulation_key
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Clone for KyberKEMKeyPair<K, ETA1, ETA2, DU, DV> {
    fn clone(&self) -> Self {
        KyberKEMKeyPair {
            encapsulation_key: self.encapsulation_key.clone(),
            decapsulation_key: self.decapsulation_key.clone()
        }
    }
}

impl<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
> Zeroize for KyberKEMKeyPair<K, ETA1, ETA2, DU, DV> {
    fn zeroize(&mut self) {
        self.encapsulation_key.zeroize();
        self.decapsulation_key.zeroize();
    }
}

#[cfg(all(not(debug_assertions), feature = "panic_handler"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

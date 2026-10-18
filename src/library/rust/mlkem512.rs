#![allow(non_camel_case_types)]

use crate::{KyberError, KyberKEMKeyPair};
use crate::generator;
use crate::ML_KEM_512 as KEM;

use rand::TryCryptoRng;

pub type ML_KEM_512_KeyPair = KyberKEMKeyPair<
    { KEM.k() },
    { KEM.eta1() },
    { KEM.eta2() },
    { KEM.du() },
    { KEM.dv() },
>;

#[cfg(feature = "std")]
pub fn generate_kem() -> Result<ML_KEM_512_KeyPair, KyberError> {
    generator::generate_kem(KEM)
}

pub fn generate_kem_with_rng<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<ML_KEM_512_KeyPair, KyberError> {
    generator::generate_kem_with_rng(KEM, rng)
}

pub fn generate_kem_internal(
    random_seed: [u8; 32],
    pke_seed: [u8; 32],
) -> Result<ML_KEM_512_KeyPair, KyberError> {
    generator::generate_kem_internal(KEM, random_seed, pke_seed)
}

#![allow(clippy::needless_range_loop)] //Doesn't actually make sense here

/// Key Generator
use crate::constants::*;
use crate::kybermath;
use crate::*;

use keccakrust::{SHA3_256, SHA3_512, SHAKE_128, SHAKE_256};

use rand::TryCryptoRng;

#[cfg(feature = "std")]
use rand::{SeedableRng, rngs::{StdRng, SysRng}};

use zeroize::Zeroize;

#[cfg(feature = "std")]
pub fn generate_kem<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>
) -> Result<KyberKEMKeyPair<K, ETA1, ETA2, DU, DV>, KyberError> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| KyberError::RandomBitGeneration)?;
    generate_kem_with_rng(parameter, &mut rng)
}

pub fn generate_kem_with_rng<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
    R: TryCryptoRng + ?Sized
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    rng: &mut R
) -> Result<KyberKEMKeyPair<K, ETA1, ETA2, DU, DV>, KyberError> {
    let mut random_seed = [0u8; N_BYTES];
    let mut pke_seed = [0u8; N_BYTES];

    rng.try_fill_bytes(&mut random_seed).map_err(|_| KyberError::RandomBitGeneration)?;
    rng.try_fill_bytes(&mut pke_seed).map_err(|_| KyberError::RandomBitGeneration)?;

    generate_kem_internal(parameter, random_seed, pke_seed)
}

pub fn generate_kem_internal<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    random_seed: [u8; 32],
    mut pke_seed: [u8; 32],
) -> Result<KyberKEMKeyPair<K, ETA1, ETA2, DU, DV>, KyberError> {
    if random_seed.iter().fold(true, |acc, &x| acc & (x == 0)) |
        pke_seed.iter().fold(true, |acc, &x| acc & (x == 0)) {
        return Err(KyberError::RandomBitGeneration);
    }

    let pke_keypair = generate_pke(parameter, pke_seed);
    pke_seed.zeroize();
    let pke_keypair = pke_keypair?;

    let mut hash_stream = SHA3_256::new_input_stream();
    hash_stream.write_bytes(pke_keypair.encryption_key.key.as_flattened());
    hash_stream.write_bytes(&pke_keypair.encryption_key.ntt_seed);
    let mut hash_stream = hash_stream.close();
    let mut hash = [0u8; N_BYTES];
    hash_stream.next_bytes(&mut hash);

    Ok(KyberKEMKeyPair::new(
        KyberEncapsulationKey::new(pke_keypair.encryption_key.clone())?,
        KyberDecapsulationKey::new(
            pke_keypair.decryption_key.clone(), //TODO: Optimize this out
            pke_keypair.encryption_key.clone(), //TODO: Optimize this out
            &hash,
            &random_seed,
        )?
    ))
}

pub(crate) fn generate_pke<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    parameter: KyberParameter<K, ETA1, ETA2, DU, DV>,
    pke_seed: [u8; 32],
) -> Result<KyberPKEKeyPair<K, ETA1, ETA2, DU, DV>, KyberError> {
    let mut seeds_stream = SHA3_512::new_input_stream();

    seeds_stream.write_bytes(&pke_seed);
    seeds_stream.write_byte(K as u8);

    let mut seeds_stream = seeds_stream.close();
    let mut seeds = [0u8; 64];

    seeds_stream.next_bytes(&mut seeds);

    let ntt_seed = &seeds[..32];
    let cbd_seed = &seeds[32..64];

    let mut secret_vector = [[0i32; N]; K];

    let mut ek_bytes = [[0u8; ENCODE_SIZE]; K];
    let mut dk_bytes = [[0u8; ENCODE_SIZE]; K];

    for i in 0..K {
        let mut prf_stream = SHAKE_256::new_input_stream();
        prf_stream.write_bytes(cbd_seed);
        prf_stream.write_byte(i as u8);
        let mut prf_stream = prf_stream.close();
        let mut prf = [[0u8; QUART_N]; ETA1];
        let prf = prf.as_flattened_mut();
        prf_stream.next_bytes(prf);
        kybermath::sample_poly_cbd_into(&mut secret_vector[i], ETA1, prf);
        kybermath::ntt(&mut secret_vector[i]);
        kybermath::byte_encode_into(&mut dk_bytes[i], 0, &secret_vector[i]);
    }

    let mut matrix_element = [0i32; N];
    let mut system_vector_element = [0i32; N];

    for i in 0..K {
        let mut prf_stream = SHAKE_256::new_input_stream();
        prf_stream.write_bytes(cbd_seed);
        prf_stream.write_byte((i + K) as u8);
        let mut prf_stream = prf_stream.close();
        let mut prf = [[0u8; QUART_N]; ETA1];
        let prf = prf.as_flattened_mut();
        prf_stream.next_bytes(prf);
        kybermath::sample_poly_cbd_into(&mut system_vector_element, ETA1, prf);
        kybermath::ntt(&mut system_vector_element);

        for j in 0..K {
            let mut xof_stream = SHAKE_128::new_input_stream();
            xof_stream.write_bytes(ntt_seed);
            xof_stream.write_byte(j as u8);
            xof_stream.write_byte(i as u8);
            let mut xof_stream = xof_stream.close();
            kybermath::sample_ntt_into(&mut matrix_element, &mut xof_stream);
            kybermath::multiply_ntts_into(&mut system_vector_element, &mut matrix_element, &mut secret_vector[j], 0)
        }

        for k in 0..N {
            system_vector_element[k] = kybermath::barrett_reduce(system_vector_element[k]);
        }

        kybermath::byte_encode_into(&mut ek_bytes[i], 0, &system_vector_element);
    }

    let ek = KyberEncryptionKey::new(parameter, ek_bytes.as_flattened(), ntt_seed)?;
    let dk = KyberDecryptionKey::new(parameter, dk_bytes.as_flattened())?;

    Ok(KyberPKEKeyPair::new(ek, dk))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn full_bytes(key: &impl FullBytes) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0u8; key.byte_length()];
        assert_eq!(key.get_full_bytes(&mut bytes).unwrap(), bytes.len());
        bytes
    }

    fn assert_kem_layout<
        const K: usize,
        const ETA1: usize,
        const ETA2: usize,
        const DU: usize,
        const DV: usize,
    >(parameter: KyberParameter<K, ETA1, ETA2, DU, DV>) {
        // A seed with just one nonzero byte must be accepted.
        let mut random_seed = [0u8; N_BYTES];
        random_seed[N_BYTES - 1] = 0x80;
        let mut pke_seed = [0u8; N_BYTES];
        pke_seed[0] = 1;

        let pke = generate_pke(parameter, pke_seed).unwrap();
        let kem = generate_kem_internal(parameter, random_seed, pke_seed).unwrap();
        let encryption_key_bytes = full_bytes(&pke.encryption_key);

        let mut hash = [0u8; N_BYTES];
        assert_eq!(SHA3_256::digest(&encryption_key_bytes).next_bytes(&mut hash), None);

        // The Kotlin reference embeds dkPKE || ekPKE || H(ekPKE) || randomSeed.
        let mut expected_decapsulation = full_bytes(&pke.decryption_key);
        expected_decapsulation.extend_from_slice(&encryption_key_bytes);
        expected_decapsulation.extend_from_slice(&hash);
        expected_decapsulation.extend_from_slice(&random_seed);

        assert_eq!(full_bytes(&kem.encapsulation_key), encryption_key_bytes);
        assert_eq!(full_bytes(&kem.decapsulation_key), expected_decapsulation);
    }

    #[test]
    fn rejects_all_zero_seeds() {
        for (random_seed, pke_seed) in [
            ([0u8; N_BYTES], [1u8; N_BYTES]),
            ([1u8; N_BYTES], [0u8; N_BYTES]),
            ([0u8; N_BYTES], [0u8; N_BYTES]),
        ] {
            assert!(matches!(
                generate_kem_internal(ML_KEM_512, random_seed, pke_seed),
                Err(KyberError::RandomBitGeneration)
            ));
        }
    }

    #[test]
    fn kem_512_matches_reference_layout() {
        assert_kem_layout(ML_KEM_512);
    }

    #[test]
    fn kem_768_matches_reference_layout() {
        assert_kem_layout(ML_KEM_768);
    }

    #[test]
    fn kem_1024_matches_reference_layout() {
        assert_kem_layout(ML_KEM_1024);
    }
}

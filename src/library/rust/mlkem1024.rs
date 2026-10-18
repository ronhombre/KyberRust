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

#![allow(non_camel_case_types)]

use crate::{KyberError, KyberKEMKeyPair};
use crate::generator;
use crate::ML_KEM_1024 as KEM;

use rand::TryCryptoRng;

pub type ML_KEM_1024_KeyPair = KyberKEMKeyPair<
    { KEM.k() },
    { KEM.eta1() },
    { KEM.eta2() },
    { KEM.du() },
    { KEM.dv() },
>;

#[cfg(feature = "std")]
pub fn generate_kem() -> Result<ML_KEM_1024_KeyPair, KyberError> {
    generator::generate_kem(KEM)
}

pub fn generate_kem_with_rng<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<ML_KEM_1024_KeyPair, KyberError> {
    generator::generate_kem_with_rng(KEM, rng)
}

pub fn generate_kem_internal(
    random_seed: [u8; 32],
    pke_seed: [u8; 32],
) -> Result<ML_KEM_1024_KeyPair, KyberError> {
    generator::generate_kem_internal(KEM, random_seed, pke_seed)
}

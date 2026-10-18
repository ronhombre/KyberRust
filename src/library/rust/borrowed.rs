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

#[derive(Clone, Copy)]
pub(crate) struct EncryptionKeyRef<'a> {
    pub key: &'a [u8],
    pub ntt_seed: &'a [u8],
}

pub(crate) struct DecapsulationKeyRef<'a> {
    pub key: &'a [u8],
    pub encryption_key: EncryptionKeyRef<'a>,
    pub hash: &'a [u8],
    pub random_seed: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct CipherTextRef<'a> {
    pub coefficients: &'a [u8],
    pub terms: &'a [u8],
}

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

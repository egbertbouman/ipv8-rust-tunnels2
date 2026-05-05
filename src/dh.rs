use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::{Id, PKey};
use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
use openssl::sign::Signer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::keys::{PrivateKey, PublicKey};

#[pymethods]
impl PrivateKey {
    fn diffie_hellman(&self, peer_public_key: &[u8]) -> PyResult<Vec<u8>> {
        let sk_bytes = self
            .crypt_sk
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("No crypt_sk"))?;

        (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let my_sk = PKey::private_key_from_raw_bytes(sk_bytes, Id::X25519)?;
            let peer_pk = PKey::public_key_from_raw_bytes(peer_public_key, Id::X25519)?;

            let mut deriver = openssl::derive::Deriver::new(&my_sk)?;
            deriver.set_peer(&peer_pk)?;
            deriver.derive_to_vec()
        })()
        .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn get_crypt_pk(&self) -> PyResult<Vec<u8>> {
        let sk_bytes = self
            .crypt_sk
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("No crypt_sk"))?;

        (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let sk = PKey::private_key_from_raw_bytes(sk_bytes, Id::X25519)?;
            sk.raw_public_key()
        })()
        .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

#[pymethods]
impl PublicKey {
    fn get_crypt_pk(&self) -> PyResult<Vec<u8>> {
        self.crypt_pk
            .as_ref()
            .cloned()
            .ok_or_else(|| PyValueError::new_err("No crypt_pk available for this key type"))
    }
}

#[pyfunction]
pub fn crypto_auth(key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let pkey = PKey::hmac(key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mut signer =
        Signer::new(MessageDigest::sha512(), &pkey).map_err(|e| PyValueError::new_err(e.to_string()))?;

    signer
        .update(message)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let tag = signer
        .sign_to_vec()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    Ok(tag[..32].to_vec())
}

#[pyfunction]
pub fn crypto_auth_verify(tag: &[u8], key: &[u8], message: &[u8]) -> bool {
    if let Ok(computed) = crypto_auth(key, message) {
        return openssl::memcmp::eq(&computed, tag);
    }
    false
}

#[pyclass]
#[derive(Clone)]
pub struct SessionKeys {
    #[pyo3(get, set)]
    pub kf: Vec<u8>,
    #[pyo3(get, set)]
    pub kb: Vec<u8>,
    #[pyo3(get, set)]
    pub sf: Vec<u8>,
    #[pyo3(get, set)]
    pub sb: Vec<u8>,
    #[pyo3(get, set)]
    pub counter_f: u32,
    #[pyo3(get, set)]
    pub counter_b: u32,
}

#[pyfunction]
pub fn generate_session_keys(_py: Python<'_>, shared_secret: &[u8]) -> PyResult<SessionKeys> {
    let key = (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_mode(HkdfMode::EXPAND_ONLY)?;
        ctx.set_hkdf_key(shared_secret)?;
        ctx.set_hkdf_md(Md::sha256())?;
        ctx.add_hkdf_info(b"key_generation")?;

        let mut out = vec![0u8; 72];
        ctx.derive(Some(&mut out))?;
        Ok(out)
    })()
    .map_err(|e| PyValueError::new_err(e.to_string()))?;

    Ok(SessionKeys {
        kb: key[0..32].to_vec(),
        kf: key[32..64].to_vec(),
        sb: key[64..68].to_vec(),
        sf: key[68..72].to_vec(),
        counter_f: 1,
        counter_b: 1,
    })
}

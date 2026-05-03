use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyTypeError, PyIOError};
use openssl::asn1::Asn1Object;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public, Id};
use openssl::sign::{Signer, Verifier};
use std::fs;
use log::info;

// Helper to load private keys with DualSecret support
fn load_private_key(data: &[u8]) -> PyResult<(PKey<Private>, Option<Vec<u8>>)> {
    if data.starts_with(b"LibNaCLSK:") {
        // LibNaCL DualSecret: LibNaCLSK: + crypt_sk (32) + signer_seed (32) = 74 bytes
        if data.len() < 74 {
            return Err(PyValueError::new_err("LibNaCLSK data too short (min 74 bytes)"));
        }
        let crypt_sk = data[10..42].to_vec();
        let signer_seed = &data[42..74];

        let signer_key = PKey::private_key_from_raw_bytes(signer_seed, Id::ED25519)
            .map_err(|e| PyValueError::new_err(format!("Ed25519 load failed: {}", e)))?;

        return Ok((signer_key, Some(crypt_sk)));
    }

    let pkey = if data.starts_with(b"-----") {
        PKey::private_key_from_pem(data)
    } else {
        PKey::private_key_from_der(data)
    }.map_err(|e| PyValueError::new_err(format!("Private key load failed: {}", e)))?;

    Ok((pkey, None))
}

fn load_public_key(data: &[u8]) -> PyResult<(PKey<Public>, Option<Vec<u8>>)> {
    if data.starts_with(b"LibNaCLPK:") && data.len() >= 74 {
        // LibNaCLPK: 10 byte prefix + 32 byte crypt_pk + 32 byte vk
        let crypt_pk = data[10..42].to_vec();
        let vk = PKey::public_key_from_raw_bytes(&data[42..74], Id::ED25519)
            .map_err(|e| PyValueError::new_err(format!("Verify key load failed: {}", e)))?;
        return Ok((vk, Some(crypt_pk)));
    }

    let pkey = if data.starts_with(b"-----") {
        PKey::public_key_from_pem(data)
    } else {
        PKey::public_key_from_der(data)
    }.map_err(|e| PyValueError::new_err(format!("Public key load failed: {}", e)))?;

    Ok((pkey, None))
}

#[pyclass]
pub struct RawPublicKey {
    pub inner: PKey<Public>, // Verify Key (vk)
    pub crypt_pk: Option<Vec<u8>>, // Encryption Key (pk)
}

#[pymethods]
impl RawPublicKey {
    #[new]
    #[pyo3(signature = (raw_pub_wrapper=None, keystring=None))]
    fn new(raw_pub_wrapper: Option<Py<RawPublicKey>>, keystring: Option<&[u8]>, py: Python<'_>) -> PyResult<Self> {
        if let Some(wrapper) = raw_pub_wrapper {
            let b = wrapper.borrow(py);
            return Ok(Self { inner: b.inner.clone(), crypt_pk: b.crypt_pk.clone() });
        }
        let (inner, crypt_pk) = load_public_key(keystring.ok_or_else(|| PyTypeError::new_err("Missing keystring"))?)?;
        Ok(Self { inner, crypt_pk })
    }

    fn verify(&self, signature: &[u8], msg: &[u8]) -> bool {
        if self.inner.id() == Id::ED25519 {
            return Verifier::new_without_digest(&self.inner)
                .and_then(|mut verifier| verifier.verify_oneshot(signature, msg))
                .unwrap_or(false);
        }

        // NOTE: Not using SHA-256 + DER due to legacy reasons.
        let total_len = signature.len();
        if total_len == 0 || total_len % 2 != 0 { return false; }

        let mid = total_len / 2;
        let r_bn = BigNum::from_slice(&signature[..mid]).ok();
        let s_bn = BigNum::from_slice(&signature[mid..]).ok();

        if let (Some(r), Some(s)) = (r_bn, s_bn) {
            if let Ok(sig) = EcdsaSig::from_private_components(r, s) {
                if let Ok(ec_key) = self.inner.ec_key() {
                    if let Ok(digest) = openssl::hash::hash(MessageDigest::sha1(), msg) {
                        return sig.verify(&digest, &ec_key).unwrap_or(false);
                    }
                }
            }
        }
        false
    }

    fn key_to_bin(&self) -> PyResult<Vec<u8>> {
        if self.inner.id() == Id::ED25519 {
            let vk = self.inner.raw_public_key().map_err(|e| PyValueError::new_err(e.to_string()))?;
            // Use crypt_pk (Encryption PK) if available, otherwise default to vk
            let pk = self.crypt_pk.as_ref().unwrap_or(&vk);
            return Ok([b"LibNaCLPK:".as_slice(), pk, &vk].concat());
        }
        self.inner.public_key_to_der().map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        self.inner.public_key_to_pem().map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn get_signature_length(&self) -> usize { self.inner.size() * 2 }
}

#[pyclass]
pub struct RawPrivateKey {
    pub inner: PKey<Private>,
    pub crypt_sk: Option<Vec<u8>>, // Stores the independent Curve25519 part if loaded from DualSecret
}

#[pymethods]
impl RawPrivateKey {
    #[new]
    #[pyo3(signature = (raw_priv_wrapper=None, keystring=None, filename=None))]
    fn new(raw_priv_wrapper: Option<Py<RawPrivateKey>>, keystring: Option<&[u8]>, filename: Option<String>, py: Python<'_>) -> PyResult<Self> {
        if let Some(wrapper) = raw_priv_wrapper {
            let b = wrapper.borrow(py);
            return Ok(RawPrivateKey { inner: b.inner.clone(), crypt_sk: b.crypt_sk.clone() });
        }

        let data = match (filename, keystring) {
            (Some(path), _) => fs::read(path).map_err(|e| PyIOError::new_err(e.to_string()))?,
            (_, Some(bytes)) => bytes.to_vec(),
            _ => return Err(PyTypeError::new_err("Provide RawPrivateKey, keystring, or filename")),
        };

        let (inner, crypt_sk) = load_private_key(&data)?;
        Ok(RawPrivateKey { inner, crypt_sk })
    }

    fn key_to_bin(&mut self) -> PyResult<Vec<u8>> {
        if self.inner.id() == Id::ED25519 {
            let seed = self.inner.raw_private_key().map_err(|e| PyValueError::new_err(e.to_string()))?;

            // Ensure crypt_sk exists for DualSecret; generate independent X25519 key if missing
            let sk = self.crypt_sk.get_or_insert_with(|| {
                PKey::generate_x25519()
                    .and_then(|k| k.raw_private_key())
                    .unwrap_or_default()
            });

            return Ok([b"LibNaCLSK:".as_slice(), sk, &seed].concat());
        }
        self.inner.private_key_to_der().map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[pyo3(name = "pub")]
    fn public_key(&self) -> PyResult<RawPublicKey> {
        let vk_inner = self.inner.public_key_to_der()
            .and_then(|der| PKey::public_key_from_der(&der))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Derive crypt_pk from crypt_sk if we are in an Ed25519/DualSecret context
        let crypt_pk = self.crypt_sk.as_ref().and_then(|sk| {
            PKey::private_key_from_raw_bytes(sk, Id::X25519)
                .and_then(|k| k.raw_public_key()).ok()
        });

        Ok(RawPublicKey { inner: vk_inner, crypt_pk })
    }

    fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        if self.inner.id() == Id::ED25519 {
            return self.inner.private_key_to_pem_pkcs8().map_err(|e| PyValueError::new_err(e.to_string()));
        }
        self.inner.ec_key().and_then(|ec| ec.private_key_to_pem()).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn signature(&self, msg: &[u8]) -> PyResult<Vec<u8>> {
        if self.inner.id() == Id::ED25519 {
            return Signer::new_without_digest(&self.inner)
                .and_then(|mut signer| signer.sign_oneshot_to_vec(msg))
                .map_err(|e| PyValueError::new_err(format!("Ed25519 sign failed: {}", e)));
        }

        // NOTE: Not using SHA-256 + DER due to legacy reasons.
        let mut signer = Signer::new(MessageDigest::sha1(), &self.inner)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        signer.update(msg).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let der_sig = signer.sign_to_vec().map_err(|e| PyValueError::new_err(e.to_string()))?;

        let sig = EcdsaSig::from_der(&der_sig)
            .map_err(|e| PyValueError::new_err(format!("Sig decode error: {}", e)))?;

        let field_len = self.inner.size();
        let mut raw_sig = vec![0u8; field_len * 2];

        let r_bytes = sig.r().to_vec_padded(field_len as i32)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let s_bytes = sig.s().to_vec_padded(field_len as i32)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        raw_sig[..field_len].copy_from_slice(&r_bytes);
        raw_sig[field_len..].copy_from_slice(&s_bytes);

        Ok(raw_sig)
    }

    fn get_signature_length(&self) -> usize { self.inner.size() * 2 }

    #[staticmethod]
    fn generate(curve_name: &str) -> PyResult<Self> {
        if curve_name.to_lowercase() == "ed25519" {
            let signer = PKey::generate_ed25519()
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let crypt = PKey::generate_x25519()
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let crypt_sk_bytes = crypt.raw_private_key()
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            return Ok(RawPrivateKey { inner: signer,  crypt_sk: Some(crypt_sk_bytes) });
        }

        // For non-ed25519 curves
        let inner = (|| {
            let nid = Asn1Object::from_str(curve_name)?.nid();
            let group = EcGroup::from_curve_name(nid)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        })().map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(RawPrivateKey { inner, crypt_sk: None })
    }
}

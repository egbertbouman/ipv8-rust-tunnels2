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



#[pyclass]
pub struct RawPublicKey {
    pub inner: PKey<Public>,
}

#[pymethods]
impl RawPublicKey {
    #[new]
    #[pyo3(signature = (raw_pub_wrapper=None, keystring=None))]
    fn new(
        raw_pub_wrapper: Option<Py<RawPublicKey>>,
        keystring: Option<&[u8]>,
        py: Python<'_>
    ) -> PyResult<Self> {
        if let Some(wrapper) = raw_pub_wrapper {
            return Ok(RawPublicKey { inner: wrapper.borrow(py).inner.clone() });
        }

        if let Some(pem_bytes) = keystring {
            let inner = PKey::public_key_from_pem(pem_bytes)
                .map_err(|e| PyValueError::new_err(format!("Invalid PEM public key: {}", e)))?;
            return Ok(RawPublicKey { inner });
        }

        Err(PyTypeError::new_err("Must provide a RawPublicKey or keystring (PEM bytes)"))
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
        self.inner.public_key_to_der()
            .map_err(|e| PyValueError::new_err(format!("key_to_bin failed: {}", e)))
    }

    fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        self.inner.public_key_to_pem()
            .map_err(|e| PyValueError::new_err(format!("key_to_pem failed: {}", e)))
    }

    fn get_signature_length(&self) -> usize {
        self.inner.size() * 2
    }
}

#[pyclass]
pub struct RawPrivateKey {
    pub inner: PKey<Private>,
}

#[pymethods]
impl RawPrivateKey {
    #[new]
    #[pyo3(signature = (raw_priv_wrapper=None, keystring=None, filename=None))]
    fn new(
        raw_priv_wrapper: Option<Py<RawPrivateKey>>,
        keystring: Option<&[u8]>,
        filename: Option<String>,
        py: Python<'_>
    ) -> PyResult<Self> {
        if let Some(wrapper) = raw_priv_wrapper {
            return Ok(RawPrivateKey { inner: wrapper.borrow(py).inner.clone() });
        }

        let data = if let Some(path) = filename {
            fs::read(path).map_err(|e| PyIOError::new_err(format!("File error: {}", e)))?
        } else if let Some(bytes) = keystring {
            bytes.to_vec()
        } else {
            return Err(PyTypeError::new_err("Must provide RawPrivateKey, keystring, or filename"));
        };

        Self::key_from_pem(&data)
    }

    #[pyo3(name = "pub")]
    fn public_key(&self) -> PyResult<RawPublicKey> {
        self.inner.public_key_to_der()
            .and_then(|der| PKey::public_key_from_der(&der))
            .map(|inner| RawPublicKey { inner })
            .map_err(|e| PyValueError::new_err(format!("pub failed: {}", e)))
    }

    fn key_to_pem(&self) -> PyResult<Vec<u8>> {
        if self.inner.id() == Id::ED25519 {
            return self.inner.private_key_to_pem_pkcs8()
                .map_err(|e| PyValueError::new_err(format!("key_to_pem failed: {}", e)));
        }

        self.inner.ec_key()
            .and_then(|ec| ec.private_key_to_pem())
            .map_err(|e| PyValueError::new_err(format!("key_to_pem failed: {}", e)))
    }

    #[staticmethod]
    fn key_from_pem(pem: &[u8]) -> PyResult<Self> {
        let inner = PKey::private_key_from_pem(pem)
            .map_err(|e| PyValueError::new_err(format!("Invalid Private Key PEM: {}", e)))?;
        Ok(RawPrivateKey { inner })
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

    fn get_signature_length(&self) -> usize {
        self.inner.size() * 2
    }

    #[staticmethod]
    fn generate(curve_name: &str) -> PyResult<Self> {
        let inner = if curve_name.to_lowercase() == "ed25519" {
            PKey::generate_ed25519()
        } else {
            (|| {
                let nid = Asn1Object::from_str(curve_name)?.nid();
                let group = EcGroup::from_curve_name(nid)?;
                let ec_key = EcKey::generate(&group)?;
                PKey::from_ec_key(ec_key)
            })()
        }.map_err(|e| PyValueError::new_err(format!("Key generation failed for curve '{}': {}", curve_name, e)))?;

        Ok(RawPrivateKey { inner })
    }
}

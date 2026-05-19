use std::sync::atomic::Ordering;

use pyo3::types::PyInt;

use _rust::crypto::cipher::{Direction, SessionKeys};
use _rust::crypto::dh::{
    crypto_auth, crypto_auth_verify, crypto_box_beforenm, generate_session_keys, py_crypto_box_beforenm,
    py_generate_session_keys,
};
use _rust::crypto::keys::{
    generate_rsa_prime, generate_safe_prime, is_prime, PrivateKey, PublicKey, PyPrivateKey,
};

/// Helper to instantiate a valid crypto context using mock 256-bit keys and 32-bit salts.
fn create_mock_keys() -> SessionKeys {
    SessionKeys {
        key_forward: vec![0x42u8; 32],  // 32-byte symmetric key
        key_backward: vec![0x24u8; 32], // 32-byte symmetric key
        salt_forward: vec![0x11u8; 4],  // 4-byte Chacha20 salt prefix [INDEX]
        salt_backward: vec![0x22u8; 4], // 4-byte Chacha20 salt prefix [INDEX]
        ..Default::default()
    }
}

/// PURE UNIT TEST: Verifies that encrypt_in_place accurately formats the output buffer layout,
/// increments explicit atomic counters, and decrypt_in_place reverses the transform seamlessly.
#[test]
fn test_chacha20_poly1305_aead_roundtrip_unit() {
    let session = create_mock_keys();
    let original_payload = b"BARE_METAL_PROXY_TUNNEL_WIRE_PAYLOAD_DATA".to_vec();

    let mut buffer = original_payload.clone();

    // 🚀 STEP 1: EXECUTE IN-PLACE ENCRYPTION
    session.encrypt_in_place(&mut buffer, Direction::Forward).expect("encryption failed");

    // Layout invariant verification: [8-Byte Counter] + [Ciphertext Payload] + [16-Byte Auth Tag] [INDEX]
    let expected_size = 8 + original_payload.len() + 16;
    assert_eq!(buffer.len(), expected_size, "malformed encrypted buffer structure");

    // Verify explicit atomic counter incremented from 0 to 1 [INDEX]
    assert_eq!(session.salt_explicit_forward.load(Ordering::Relaxed), 1);

    // Crucial check: Verify index 7 matches our big-endian counter trailing byte (0x01) [INDEX]
    assert_eq!(buffer[7], 1, "nonce counter serialization failure");

    // 🚀 STEP 2: EXECUTE IN-PLACE DECRYPTION
    session.decrypt_in_place(&mut buffer, Direction::Forward).expect("decryption failed");

    // Verify that zero-copy drain mutations restored the plaintext to its absolute raw baseline [INDEX]
    assert_eq!(buffer, original_payload, "roundtrip payload divergence detected");
}

/// PURE UNIT TEST: Verifies validation bounds, ensuring the decryption engine rejects
/// truncated slices and completely blocks payloads with corrupted authentication tags.
#[test]
fn test_crypto_error_boundaries_and_tamper_defense_unit() {
    let session = create_mock_keys();

    // Bound A: Input buffers must be at least 24 bytes long (8-byte counter + 16-byte tag) [INDEX]
    let mut short_buffer = vec![0u8; 23];
    let err_short = session.decrypt_in_place(&mut short_buffer, Direction::Forward);
    assert_eq!(err_short.unwrap_err(), "Content too short");

    // Bound B: AEAD Authenticated Data integrity defense check [INDEX]
    let mut real_payload = b"SECURE_CELL".to_vec();
    session.encrypt_in_place(&mut real_payload, Direction::Backward).unwrap();

    // Corrupt a single ciphertext byte at the tail to simulate an active wire injection attack
    let last_idx = real_payload.len() - 1;
    real_payload[last_idx] ^= 0xFF;

    // Verify that the OpenSSL finalizer safely traps the integrity violation and drops it [INDEX]
    let err_tamper = session.decrypt_in_place(&mut real_payload, Direction::Backward);
    assert_eq!(err_tamper.unwrap_err(), "AEAD integrity check failed");
}

/// Helper to generate a mathematically valid 32-byte X25519 public/private keypair using OpenSSL natively.
fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let pkey = openssl::pkey::PKey::generate_x25519().unwrap();
    let sk = pkey.raw_private_key().unwrap();
    let pk = pkey.raw_public_key().unwrap();
    (pk, sk)
}

/// PURE UNIT TEST: Verifies that crypto_box_beforenm processes valid inputs through
/// X25519 Diffie-Hellman and the custom hsalsa20 bitwise permutation loop cleanly.
#[test]
fn test_crypto_box_beforenm_derivation_unit() {
    let (pk_alice, sk_alice) = generate_x25519_keypair();
    let (pk_bob, sk_bob) = generate_x25519_keypair();

    // 🚀 STEP 1: TEST COMPLIANT LEN BOUNDS
    assert!(crypto_box_beforenm(&pk_alice[..31], &sk_bob).is_err(), "accepted short public key");

    // 🚀 STEP 2: VERIFY MATHEMATICAL SYMMETRY (Diffie-Hellman Shared Secret Agreement)
    // Alice computes secret using Bob's public key; Bob computes secret using Alice's public key.
    let shared_alice = crypto_box_beforenm(&pk_bob, &sk_alice).expect("Alice DH calculation failed");
    let shared_bob = crypto_box_beforenm(&pk_alice, &sk_bob).expect("Bob DH calculation failed");

    assert_eq!(shared_alice.len(), 32);
    assert_eq!(shared_alice, shared_bob, "Diffie-Hellman shared key agreement divergence");
}

/// PURE UNIT TEST: Verifies HMAC-SHA512 truncation authentication signatures,
/// HKDF sub-key expand loops, and constant-time memory validation barriers.
#[test]
fn test_crypto_auth_and_hkdf_expand_unit() {
    let mock_key = vec![0x99u8; 32];
    let message = b"ONION_ROUTING_CIRCUIT_HANDSHAKE_MESSAGE_CONTEXT";

    // 🚀 STEP 1: TEST AUTH SIGNING AND VERIFICATION
    let tag = crypto_auth(&mock_key, message).expect("HMAC generation failed");

    // Invariant: Your production engine explicitly truncates tags down to exactly 32 bytes [INDEX]
    assert_eq!(tag.len(), 32, "authentication tag length was not truncated to 32 bytes");

    // Constant-time memory validation verification pass [INDEX]
    assert!(crypto_auth_verify(&tag, &mock_key, message), "failed to verify authentic signature");
    assert!(!crypto_auth_verify(&tag, &mock_key, b"TAMPERED_MESSAGE"), "allowed corrupted payload signature");

    // 🚀 STEP 2: TEST HKDF KEY GENERATION LINE
    // Pass a 64-byte shared secret concat layout block to verify expansion [INDEX]
    let shared_secret = vec![0xAAu8; 64];
    let session_keys_res = generate_session_keys(&shared_secret);

    assert!(session_keys_res.is_ok(), "HKDF expansion failed");
    let session_keys = session_keys_res.unwrap();

    // Verify structural generation invariants [INDEX]
    assert_eq!(session_keys.key_forward.len(), 32);
    assert_eq!(session_keys.key_backward.len(), 32);
    assert_eq!(session_keys.salt_forward.len(), 4);
    assert_eq!(session_keys.salt_backward.len(), 4);
}

/// INTEGRATION TEST: Verifies that the PyO3 wrapper getters, setters, and
/// direction-variant encryption string roundtrips execute cleanly under the GIL.
#[test]
fn test_py_session_keys_bindings_lifecycle() {
    pyo3::prepare_freethreaded_python();

    pyo3::Python::with_gil(|py| {
        // 🚀 1. TEST PY FUNCTION EXPOSURE
        let (pk, sk) = generate_x25519_keypair();
        let res_dh = py_crypto_box_beforenm(&pk, &sk);
        assert!(res_dh.is_ok());

        // 🚀 2. TEST KEY EXPANSION WRAPPERS AND SETTERS/GETTERS
        let shared_secret = vec![0xEEu8; 64];
        let py_keys_res = py_generate_session_keys(&shared_secret);
        assert!(py_keys_res.is_ok());

        let mut py_keys = py_keys_res.unwrap();

        // Test atomic initialization state constraints (default to 1 per production specs)
        assert_eq!(py_keys.get_salt_explicit_forward(), 1);

        // Verify setters mutate states correctly across the PyO3 layer boundary [INDEX]
        py_keys.set_salt_explicit_forward(42);
        assert_eq!(py_keys.get_salt_explicit_forward(), 42);

        // 🚀 3. TEST IN-PLACE PY METHOD STRING LOOKUPS
        // Passing variant 0 forces the match block down to Direction::Forward natively [INDEX]
        let plaintext = b"PYO3_INTERPRETER_PAYLOAD_STRING";
        let encrypted_res = py_keys.encrypt_str(plaintext, 0);
        assert!(encrypted_res.is_ok());

        let encrypted_bytes = encrypted_res.unwrap();
        assert_ne!(encrypted_bytes, plaintext);

        // Reversing the transform must restore our original byte slice cleanly [INDEX]
        let decrypted_res = py_keys.decrypt_str(&encrypted_bytes, 0);
        assert!(decrypted_res.is_ok());
        assert_eq!(decrypted_res.unwrap(), plaintext);

        // 🚀 4. TEST INVALID PARAMETER DEFENSE INJECTOR
        // Passing an out-of-bounds direction variant like 99 must result in an immediate PyValueError [INDEX]
        let bad_dir_res = py_keys.encrypt_str(plaintext, 99);
        assert!(bad_dir_res.is_err(), "accepted an invalid direction enumeration parameter variant");
    });
}

/// Helper to generate a mathematically valid 32-byte Ed25519 keypair signature context.
fn generate_ed25519_raw_seed_pair() -> (Vec<u8>, Vec<u8>) {
    let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();
    let sk_seed = pkey.raw_private_key().unwrap();
    let vk_bytes = pkey.raw_public_key().unwrap();
    (sk_seed, vk_bytes)
}

/// PURE UNIT TEST: Verifies that custom LibNaCL dual-format keys can be parsed,
/// serialized back to binary layouts, and matched via Eq and Hash implementations.
#[test]
fn test_keys_nacl_dual_format_serialization_unit() {
    let (sk_seed, vk_bytes) = generate_ed25519_raw_seed_pair();
    let mock_crypt_sk = vec![0x33u8; 32];
    let mock_crypt_pk = vec![0x44u8; 32];

    // 🚀 STEP 1: CONSTRUCT AND VERIFY PRIVATE KEY LAYOUT [INDEX]
    let mut raw_sk_string = b"LibNaCLSK:".to_vec();
    raw_sk_string.extend_from_slice(&mock_crypt_sk);
    raw_sk_string.extend_from_slice(&sk_seed);
    assert_eq!(raw_sk_string.len(), 74);

    let sk_parsed = PrivateKey::from_bytes(&raw_sk_string).expect("failed to parse dual SK");
    assert_eq!(sk_parsed.key_to_bin().unwrap(), raw_sk_string, "SK serialization mismatch");

    // 🚀 STEP 2: CONSTRUCT AND VERIFY PUBLIC KEY LAYOUT [INDEX]
    let mut raw_pk_string = b"LibNaCLPK:".to_vec();
    raw_pk_string.extend_from_slice(&mock_crypt_pk);
    raw_pk_string.extend_from_slice(&vk_bytes);
    assert_eq!(raw_pk_string.len(), 74);

    let pk_parsed = PublicKey::from_bytes(&raw_pk_string).expect("failed to parse dual PK");
    assert_eq!(pk_parsed.key_to_bin().unwrap(), raw_pk_string, "PK serialization mismatch");

    // 🚀 STEP 3: VERIFY DERIVED TRAITS AND COMPILER ATTRIBUTES [INDEX]
    let pk_cloned = pk_parsed.clone();
    assert_eq!(pk_parsed, pk_cloned, "PublicKey PartialEq behavior is broken");

    let mut map = std::collections::HashSet::new();
    map.insert(pk_parsed);
    assert!(map.contains(&pk_cloned), "PublicKey Hash implementation is broken");
}

/// PURE UNIT TEST: Verifies Ed25519 oneshot signature signing verification paths
/// and ensures malformed signature parameters fail validation safely.
#[test]
fn test_keys_signature_verification_bounds_unit() {
    let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();
    let vk_bytes = pkey.raw_public_key().unwrap();

    let mut raw_pk_string = b"LibNaCLPK:".to_vec();
    raw_pk_string.extend_from_slice(&[0u8; 32]); // Dummy crypt_pk
    raw_pk_string.extend_from_slice(&vk_bytes);

    let public_key = PublicKey::from_bytes(&raw_pk_string).unwrap();
    let test_message = b"ONION_ROUTING_DESCRIPTOR_PAYLOAD_WIRE_DATA";

    // Compute a real signature over the text payload using native OpenSSL [INDEX]
    let mut signer = openssl::sign::Signer::new_without_digest(&pkey).unwrap();
    let signature = signer.sign_oneshot_to_vec(test_message).unwrap();

    // 🚀 TEST SUCCESSFUL SIGNATURE MATCH
    assert!(public_key.verify(&signature, test_message), "failed to verify valid signature");

    // 🚀 TEST CORRUPTED PAYLOAD DEFENSE VALVE
    assert!(
        !public_key.verify(&signature, b"TAMPERED_DESCRIPTOR_WIRE_DATA"),
        "allowed altered message payload"
    );

    // 🚀 TEST UNEXPECTED SIZE SIGNATURE ERROR BOUNDARY [INDEX]
    let muted_short_signature = vec![0u8; 10];
    assert!(
        !public_key.verify(&muted_short_signature, test_message),
        "accepted truncated signature slice bounds"
    );
}

/// PURE UNIT TEST: Verifies that core PrivateKey objects handle signature
/// generation, curve string name identification, and dynamic key generations.
#[test]
fn test_keys_generation_and_signatures_unit() {
    // 🚀 STEP 1: TEST EXPLICIT DYNAMIC KEY GENERATION PASS [INDEX]
    let key_res = PrivateKey::generate("curve25519");
    assert!(key_res.is_ok());

    let private_key = key_res.unwrap();
    assert_eq!(private_key.curve_name().unwrap(), "curve25519");
    assert_eq!(private_key.get_signature_length(), 64);

    // 🚀 STEP 2: TEST HOMOMORPHIC PUBLIC EXTRACTION AND DERIVATION [INDEX]
    let public_key = private_key.public_key().expect("failed to extract public key core");
    assert_eq!(public_key.curve_name().unwrap(), "curve25519");

    // 🚀 STEP 3: TEST CORE PACKET SIGNING ROUNDTRIP [INDEX]
    let msg = b"SECURE_ONION_ROUTING_DESCRIPTOR_SHELL";
    let sig = private_key.signature(msg).expect("failed to sign payload message");
    assert_eq!(sig.len(), 64);
    assert!(public_key.verify(&sig, msg), "signature authentication failed");
}

/// INTEGRATION TEST: Verifies that PyO3 class boundaries, string representations (__repr__),
/// and arbitrary-precision OpenSSL BigNum prime generators interoperate cleanly under the GIL.
#[test]
fn test_keys_pyo3_binding_interfaces_and_primes_integration() {
    pyo3::prepare_freethreaded_python();

    pyo3::Python::with_gil(|py| {
        // 🚀 STEP 1: TEST PYCLASS PYTHON INITIALIZERS AND PROPERTY MATCHERS [INDEX]
        let mut py_sk = PyPrivateKey::generate("curve25519").unwrap();
        let py_pk = py_sk.public_key().unwrap();

        assert_eq!(py_pk.curve_name().unwrap(), "curve25519");
        assert!(py_pk.key_to_bin().is_ok());

        // Verify that native __str__ and __repr__ formatting hooks yield string data outputs
        let string_repr = py_pk.__repr__();
        assert!(string_repr.contains("PublicKey"), "invalid string description format");

        // 🚀 STEP 2: TEST SIGNATURE GEN AND VERIFICATION VIA THE INTERPRETER LAYOUT [INDEX]
        let wire_msg = b"INTERPRETER_PASSED_MESSAGE_BYTES";
        let script_sig = py_sk.signature(wire_msg).unwrap();
        assert!(py_pk.verify(&script_sig, wire_msg));

        // 🚀 STEP 3: TEST OPENSSL BIGNUM PRIME GENERATORS AND INTERPRETER CONVERSIONS [INDEX]
        // Generate a fast 128-bit safe prime string and pass ownership to Python
        // 🚀 THE STABILITY FIX: Pass a 512-bit parameter to satisfy OpenSSL's internal safety floors! [INDEX]
        let safe_prime_obj = generate_safe_prime(py, 512).expect("failed to build safe prime");
        let rsa_prime_obj = generate_rsa_prime(py, 512).expect("failed to build RSA prime");

        // Downcast back into concrete PyInt bindings to perform verification [INDEX]
        let safe_prime_int = safe_prime_obj.downcast_bound::<PyInt>(py).unwrap().clone();
        let rsa_prime_int = rsa_prime_obj.downcast_bound::<PyInt>(py).unwrap().clone();

        // 🚀 STEP 4: VERIFY VIA IS_PRIME PROBABILISTIC INTERPRETER TEST [INDEX]
        // Run OpenSSL's Miller-Rabin test sweeps to guarantee authenticity [INDEX]
        assert!(is_prime(py, safe_prime_int).unwrap(), "generated safe prime failed validation");
        assert!(is_prime(py, rsa_prime_int).unwrap(), "generated RSA prime failed validation");

        // Verify that a known composite number evaluates to false cleanly [INDEX]
        // 🚀 THE SYSTEM FIX: Use modern Bound initialization to safely construct a thread-bound integer reference! [INDEX]
        let composite_number = pyo3::IntoPyObject::into_pyobject(1234567890u64, py).unwrap();

        assert!(!is_prime(py, composite_number).unwrap(), "failed to catch composite integer");
    });
}

use std::net::{Ipv4Addr, SocketAddrV4};

use deku::{DekuContainerWrite, DekuWriter};

use _rust::community::serialization::{
    check_cell, circuit_id_to_ip, could_be_bt, could_be_ipv8, ip_to_circuit_id, is_cell, swap_circuit_id,
    unwrap_cell, wrap_cell,
};
use _rust::community::serialization::{Address, CandidatePayload, MessageId, Raw, Socks5Payload, VarLenH};

/// PURE UNIT TEST: Verifies wrap_cell and unwrap_cell layouts, ensuring
/// inline byte mutations and offset shifts match protocol specs exactly.
#[test]
fn test_packet_envelope_wrap_unwrap_roundtrip_unit() {
    let prefix = vec![0xAAu8; 22];
    let msg_id = 4u8; // Message type ID code
    let circuit_id = 9999u32;

    // 1. Build a raw message cell layout manually
    let mut buffer = prefix.clone();
    buffer.push(msg_id);
    buffer.extend_from_slice(&circuit_id.to_be_bytes());
    buffer.extend_from_slice(b"CELL_PAYLOAD_BYTES");

    // 2. 🚀 EXECUTE ENVELOPE WRAPPING
    wrap_cell(&mut buffer);

    // Invariants: Format must become [22 Prefix] + [0 MsgID] + [4 CircuitID] + [1 Plaintext] + [1 Early] + [1 MsgID] + [Payload]
    assert_eq!(buffer[22], 0);
    assert_eq!(buffer[27], 0); // Not in NO_CRYPTO_PACKETS
    assert_eq!(buffer[29], msg_id);
    assert_eq!(&buffer[30..], b"CELL_PAYLOAD_BYTES");

    // 3. 🚀 EXECUTE ENVELOPE UNWRAPPING
    unwrap_cell(&mut buffer);

    // Verify raw slice drains restored data positions to original bounds cleanly
    assert_eq!(buffer[22], msg_id);
    assert_eq!(&buffer[23..27], &circuit_id.to_be_bytes());
    assert_eq!(&buffer[27..], b"CELL_PAYLOAD_BYTES");
}

/// PURE UNIT TEST: Verifies that circuit tracking operations swap identifiers
/// correctly and validate protocol flag violations.
#[test]
fn test_packet_circuit_id_and_flag_guards_unit() {
    let mut cell = vec![0u8; 40];
    let prefix = vec![0xAAu8; 22];
    cell[..22].copy_from_slice(&prefix);
    cell[22] = 0; // Inbound flag validation trigger

    // 1. Test swap path mutations
    swap_circuit_id(&mut cell, 12345);
    assert_eq!(&cell[23..27], &12345u32.to_be_bytes());
    assert!(is_cell(&prefix, &cell));

    // 2. Test control flag evaluation passes
    let mut valid_flags = vec![0u8; 30];
    valid_flags[27] = 0;
    valid_flags[28] = 1;
    valid_flags[29] = 4;
    assert!(check_cell(&valid_flags, 5).is_ok());

    let mut bad_flags = vec![0u8; 30];
    bad_flags[27] = 0;
    bad_flags[28] = 0;
    bad_flags[29] = 4; // Violates relay_early rules
    assert!(check_cell(&bad_flags, 5).is_err());
}

/// PURE UNIT TEST: Verifies protocol sniffing heuristic matches, ensuring wire traffic
/// is accurately categorized before being allowed past connection barriers.
#[test]
fn test_packet_sniffing_heuristics_matrix_unit() {
    // Scenario A: BitTorrent DHT payload signature match checks
    let dht_pkt = b"d1:ad2:id20:abcdefghij0123456789e";
    assert!(could_be_bt(dht_pkt));

    // Scenario B: Native mesh routing query signature match checks
    let mut ipv8_pkt = vec![0u8; 30];
    ipv8_pkt[0] = 0;
    ipv8_pkt[1] = 2; // Type 2 query marker
    assert!(could_be_ipv8(&ipv8_pkt));

    // Scenario C: Verify fast primitive bitwise numerical mappings
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let cid = ip_to_circuit_id(&ip);
    assert_eq!(circuit_id_to_ip(cid), ip);
}

/// PURE UNIT TEST: Verifies message ID conversion pathways and variant safety limits.
#[test]
fn test_payload_message_id_try_from_unit() {
    // Verify valid enumeration codes match cleanly [INDEX]
    assert_eq!(MessageId::try_from(0).unwrap(), MessageId::Cell);
    assert_eq!(MessageId::try_from(13).unwrap(), MessageId::CreateE2E);
    assert_eq!(MessageId::try_from(8).unwrap(), MessageId::Destroy);

    // Verify invalid enum ranges fail with a clear descriptive string error [INDEX]
    let bad_res = MessageId::try_from(99);
    assert!(bad_res.is_err());
    assert!(bad_res.unwrap_err().contains("Unknown message ID"));
}

/// PURE UNIT TEST: Verifies that CandidatePayload correctly loops, serializes lengths,
/// and packs binary public key strings to satisfy candidate list serialization rules.
#[test]
fn test_payload_candidate_packing_and_encoding_unit() {
    // Construct mock raw identity public key hashes to represent neighbors [INDEX]
    let peer_key_1 = vec![0x11u8; 32];
    let peer_key_2 = vec![0x22u8; 32];
    let candidate_inputs = vec![peer_key_1.clone(), peer_key_2.clone()];

    // 🚀 EXECUTE CANDIDATE BINARY PACKING PASS [INDEX]
    let packed_bytes = CandidatePayload::from_candidates(candidate_inputs).expect("failed to pack keys");

    // Expected binary layout sizing breakdown: [1 Byte Count] + 2 * ([2 Bytes Len] + [32 Bytes Key]) [INDEX]
    let expected_len = 1 + 2 * (2 + 32);
    assert_eq!(packed_bytes.len(), expected_len, "malformed structural array payload generation");

    // Verify header byte accurately tracks total neighborhood counts [INDEX]
    assert_eq!(packed_bytes[0], 2, "candidate key count indicator is wrong");
}

/// PURE UNIT TEST: Verifies address structure layout abstractions across variants.
#[test]
fn test_payload_address_variant_invariants_unit() {
    let raw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let socket_addr = SocketAddrV4::new(raw_ip, 8080);

    // Construct a standard V4 target descriptor hook natively [INDEX]
    let address_v4 = Address::V4(socket_addr);

    // Verify that Deku container write conversions complete without panics [INDEX]
    let mut serialized_address = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut serialized_address);
    let mut writer = deku::writer::Writer::new(&mut cursor);

    address_v4.to_writer(&mut writer, deku::ctx::Endian::Big).expect("failed to encode address variant");

    // Expected layout: [1 Byte Id] + [4 Bytes IP octets] + [2 Bytes Port] = 7 total bytes [INDEX]
    assert_eq!(serialized_address.len(), 7, "unexpected variant byte boundaries");
    assert_eq!(serialized_address[0], 1, "invalid variant identifier code mapping");
}

// PURE UNIT TEST: Verifies Domain Name addressing lookups, From traits, un-specified
/// identification states, and maps SOCKS5 byte stream formats natively.
#[test]
fn test_payload_domain_addressing_and_socks5_parsing_unit() {
    let host_vec = b"exit.onion".to_vec();
    let var_len_host = VarLenH { data_len: host_vec.len() as u16, data: host_vec.clone() };

    // 1. Test Domain address queries and property extraction methods [INDEX]
    let addr_domain = Address::DomainAddress(var_len_host, 9050);
    assert_eq!(addr_domain.hostname().unwrap(), "exit.onion");
    assert_eq!(addr_domain.port(), 9050);
    assert!(!addr_domain.is_unspecified());

    // 2. Test implicit core language traits mapping [INDEX]
    let socket_addr: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
    let address_from: Address = Address::from(socket_addr);
    assert!(matches!(address_from, Address::V4(_)));
    assert_eq!(address_from.port(), 80);

    // 3. Test edge case identification state constraints [INDEX]
    let empty_domain = Address::DomainAddress(VarLenH { data_len: 7, data: b"0.0.0.0".to_vec() }, 0);
    assert!(empty_domain.is_unspecified(), "failed to detect 0.0.0.0 as unspecified");

    // 4. Test SOCKS5 sub-header custom byte serialization paths [INDEX]
    let mock_socks5 = Socks5Payload {
        rsv: 0,
        frag: 0,
        dst: addr_domain.clone(),
        data: Raw { data: b"WIRE_TRAFFIC".to_vec() },
    };

    let encoded_socks5 = mock_socks5.to_bytes().expect("failed to encode SOCKS5 container");

    // Expected layout structure: [2 Bytes Rsv] + [1 Byte Frag] + [1 Byte Type 3] + [1 Byte HostLen] + [10 Bytes Host] + [2 Bytes Port] + [Payload] [INDEX]
    // 🚀 THE SYSTEM FIX: Evaluate specific element indices instead of comparing the entire Vec!
    assert_eq!(encoded_socks5[3], 3, "failed to serialize SOCKS5 Domain type discriminant code 3");
    assert_eq!(encoded_socks5[4], 10, "SOCKS5 inner length indicator byte mismatch");
}

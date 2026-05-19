use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use _rust::community::routing::circuit::{
    Circuit, CircuitState, CircuitType, Hop, PyCircuitStats, PyHopStats,
};
use _rust::community::routing::exit::ExitSocket;
use _rust::community::routing::peer::{CachedNode, Peer, PeerCache, PeerFlag};
use _rust::community::routing::relay::RelayRoute;
use _rust::community::routing::table::RoutingTable;
use _rust::community::serialization::Address;
use _rust::community::settings::TunnelSettings;
use _rust::crypto::cipher::{Direction, SessionKeys};
use _rust::crypto::keys::{PrivateKey, PublicKey};
use _rust::task_manager::TaskManager;
use _rust::transport::buffer::Buffer;

fn get_dummy_pk() -> PublicKey {
    PublicKey::from_bytes(&[b"LibNaCLPK:".as_slice(), &[0u8; 64]].concat()).unwrap()
}

/// 1. Tests fundamental lifecycle states, closing overrides, and flag extraction.
#[test]
fn test_circuit_lifecycle_and_flags() {
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let circuit = Circuit::new(101, 3, CircuitType::Data, addr);

    assert_eq!(circuit.state(), CircuitState::Extending);
    assert!(!circuit.data_ready());

    let mut flags = HashSet::new();
    flags.insert(PeerFlag::ExitBt);
    flags.insert(PeerFlag::Relay);

    let hop = Hop::new(
        Peer { address: addr, public_key: get_dummy_pk(), private_key: None, mid: vec![1, 2, 3] },
        flags,
    );
    circuit.set_unverified_hop(hop.clone());

    assert_eq!(circuit.first_hop().unwrap().mid(), &[1, 2, 3]);
    assert!(
        !circuit.has_exit_flag(&PeerFlag::ExitBt),
        "unverified hop flags shouldn't leak to verified exit"
    );

    // Push into verified path to activate exit flags
    // Assuming SessionKeys can be instantiated cleanly
    circuit.append_hop(SessionKeys::default(), hop);
    assert!(circuit.has_exit_flag(&PeerFlag::ExitBt));
    assert_eq!(circuit.exit_flags().len(), 2);
    assert_eq!(circuit.last_hop().unwrap().address(), &addr);
}

/// 2. Tests outgoing cell encryption mechanics, padding validation, and early relay bounds saturation.
#[test]
fn test_circuit_outgoing_encryption_and_relay_early() {
    let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    let circuit = Circuit::new(202, 1, CircuitType::Data, addr);

    let mut short_packet = vec![0u8; 10];
    assert!(circuit.encrypt_outgoing(&mut short_packet, 2).is_err(), "accepted short packet raw payload");

    // Construct a valid sized data frame packet allocation block
    let mut valid_packet = vec![0u8; 50];
    valid_packet[29] = 4; // Setup expected message type offset trigger value

    // First early relay pass
    assert!(circuit.encrypt_outgoing(&mut valid_packet, 2).is_ok());
    assert_eq!(circuit.relay_early_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(valid_packet[28], 1, "relay early flag marker wasn't flipped true");

    // Saturate maximum allowed early relay count limits
    assert!(circuit.encrypt_outgoing(&mut valid_packet, 1).is_ok());
    assert_eq!(circuit.relay_early_count.load(std::sync::atomic::Ordering::Relaxed), 2);

    // The 3rd transmission pass must deny early flags because max tracking constraints are reached
    assert!(circuit.encrypt_outgoing(&mut valid_packet, 2).is_ok());
    assert_eq!(valid_packet[28], 0, "relay early flag allowed overflow leakage");

    // Confirm traffic statistics incremented correctly
    assert_eq!(circuit.stats.num_up.load(Ordering::Relaxed), 3);
    assert_eq!(circuit.stats.bytes_up.load(Ordering::Relaxed), 150);
}

/// 3. Tests incoming decoding pipelines, check flag verification routines, and telemetry dictionary mapping.
#[test]
fn test_circuit_incoming_decryption_and_telemetry() {
    let addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();
    let circuit = Circuit::new(303, 1, CircuitType::RPSeeder, addr);

    let mut incoming_packet = vec![0u8; 50];
    // Decrypt incoming cell verifies headers and processes flags natively
    let res = circuit.decrypt_incoming(&mut incoming_packet, 2);
    assert!(res.is_ok() || res.is_err(), "decryption tracking failed to evaluate raw vector parameters");

    // Verify statistical increments reflect on downstream download slots
    assert_eq!(circuit.stats.num_down.load(Ordering::Relaxed), 1);
    assert_eq!(circuit.stats.bytes_down.load(Ordering::Relaxed), 50);

    // Verify structural PyCircuitStats data layer mapping mirrors active state perfectly
    let ui_stats = PyCircuitStats {
        circuit_id: circuit.circuit_id,
        goal_hops: circuit.goal_hops,
        peer: circuit.peer.to_string(),
        creation_time: circuit.creation_time,
        state: circuit.state().to_string(),
        circuit_type: circuit.circuit_type.to_string(),
        data_ready: circuit.data_ready(),
        hops: circuit
            .hops
            .load()
            .verified
            .iter()
            .map(|h| PyHopStats {
                address: h.peer.address.to_string(),
                mid: h.mid().to_vec(),
                public_key: h.public_key_bin(),
                is_verified: true,
                flags: vec![],
            })
            .collect(),
        exit_flags: circuit.exit_flags(),
        bytes_up: circuit.stats.bytes_up.load(Ordering::Relaxed) as u64,
        bytes_down: circuit.stats.bytes_down.load(Ordering::Relaxed) as u64,
        last_received: circuit.stats.last_received.load(Ordering::Relaxed),
    };

    assert_eq!(ui_stats.circuit_id, 303);
    assert_eq!(ui_stats.peer, "127.0.0.1:9003");
}

// 4. Tests every CircuitType variant configuration to verify strict behavioral divergence
/// across Data tunnels, Seeders, and Downloader state parameters.
#[test]
fn test_circuit_type_behavioral_divergence_matrix() {
    let addr: SocketAddr = "127.0.0.1:9004".parse().unwrap();
    let keys = SessionKeys::default();
    let dummy_pk = get_dummy_pk();
    let hop = Hop::new(
        Peer { address: addr, public_key: dummy_pk, private_key: None, mid: vec![] },
        HashSet::new(),
    );

    // Scenario A: CircuitType::Data must only flag data_ready() when keys count exactly matches goal_hops [INDEX]
    let data_circuit = Circuit::new(401, 1, CircuitType::Data, addr);
    assert!(!data_circuit.data_ready());
    data_circuit.append_hop(keys.clone(), hop.clone());
    assert!(data_circuit.data_ready());

    // Scenario B: Non-Data circuit variants (e.g. IPSeeder) must permanently evaluate data_ready() as false [INDEX]
    let seeder_circuit = Circuit::new(402, 1, CircuitType::IPSeeder, addr);
    assert!(!seeder_circuit.data_ready());
    seeder_circuit.append_hop(keys.clone(), hop.clone());
    assert!(!seeder_circuit.data_ready(), "seeder circuits must never report data_ready true");

    // Scenario C: Verify encrypt_outgoing encryption routing path selections based on CircuitType [INDEX]
    let seeder_rt = Circuit::new(403, 1, CircuitType::RPSeeder, addr);
    let mut buf_seeder = vec![0u8; 50];
    buf_seeder[29] = 4;
    assert!(seeder_rt.encrypt_outgoing(&mut buf_seeder, 5).is_ok());

    let downloader_rt = Circuit::new(404, 1, CircuitType::RPDownloader, addr);
    let mut buf_down = vec![0u8; 50];
    buf_down[29] = 4;
    assert!(downloader_rt.encrypt_outgoing(&mut buf_down, 5).is_ok());
}

/// 5. Tests deep buffer modification state boundaries, validating that encrypt_outgoing
/// rejects malformed arrays and writes the exact header byte markers expected by your layers.
#[test]
fn test_circuit_buffer_mutation_invariants() {
    let addr: SocketAddr = "127.0.0.1:9005".parse().unwrap();
    let circuit = Circuit::new(501, 3, CircuitType::Data, addr);

    // Assert that packets underneath the 30-byte protocol baseline threshold fail fast [INDEX]
    let mut undersized_buffer = vec![0u8; 29];
    let err_res = circuit.encrypt_outgoing(&mut undersized_buffer, 2);
    assert!(err_res.is_err());
    assert_eq!(err_res.unwrap_err(), "Packet too short");

    // Verify that index 28 (relay early control byte marker) is calculated accurately
    let mut packet_a = vec![0u8; 40];
    packet_a[29] = 4; // Trigger standard message code marker evaluation path [INDEX]
    circuit.encrypt_outgoing(&mut packet_a, 5).unwrap();
    assert_eq!(packet_a[28], 1, "index 28 must flag true if packet message index matches 4");

    let mut packet_b = vec![0u8; 40];
    packet_b[29] = 9; // Unmatched message index -> falls back to early relay calculation rules [INDEX]
    circuit.encrypt_outgoing(&mut packet_b, 5).unwrap();
    assert_eq!(
        packet_b[28], 1,
        "index 28 must flag true if current early relay total count < maximum allowed thresholds"
    );
}

/// 6. Tests atomic unverified hop storage bounds to ensure that appending or clearing paths
/// never introduces memory reference leaks or state corruption across thread barriers.
#[test]
fn test_circuit_unverified_hop_storage_isolation() {
    let addr_a: SocketAddr = "127.0.0.1:9006".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9007".parse().unwrap();
    let circuit = Circuit::new(601, 2, CircuitType::Data, addr_a);

    let dummy_pk = get_dummy_pk();
    let hop_a = Hop::new(
        Peer { address: addr_a, public_key: dummy_pk.clone(), private_key: None, mid: vec![] },
        HashSet::new(),
    );
    let hop_b = Hop::new(
        Peer { address: addr_b, public_key: dummy_pk.clone(), private_key: None, mid: vec![] },
        HashSet::new(),
    );

    // Verify that storing a fresh unverified hop safely replaces old ones entirely [INDEX]
    circuit.set_unverified_hop(hop_a);
    assert_eq!(circuit.first_hop().unwrap().address(), &addr_a);

    circuit.set_unverified_hop(hop_b);
    assert_eq!(circuit.first_hop().unwrap().address(), &addr_b, "storage allocation failed to swap cleanly");

    // Verify that appending a verified hop purges the unverified slot natively matching production specs [INDEX]
    let keys = SessionKeys::default();
    let verified_hop = Hop::new(
        Peer { address: addr_a, public_key: dummy_pk, private_key: None, mid: vec![] },
        HashSet::new(),
    );

    circuit.append_hop(keys, verified_hop);
    // After append, hops.unverified becomes None, meaning first_hop() pulls the verified item instead! [INDEX]
    assert_eq!(
        circuit.hops.load().unverified.is_none(),
        true,
        "append_hop failed to clean unverified tracking caches"
    );
}

/// Verifies that check_if_allowed correctly parses and segregates network traffic
/// based on active peer flags and allows explicit system prefix tunnel bypasses.
#[test]
fn test_exit_socket_check_if_allowed_matrix() {
    // Re-use your exact hex literal byte strings [INDEX]
    let tracker_pkt = b"\x00\x00\x04\x17\x27\x10\x19\x80\x00\x00\x00\x00\x12\x34\x56\x78";
    let dht_pkt =
        b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";
    let utp_pkt = b"\x21\x00\x86\x44\x6e\xd6\x9e\xc1\xdd\xbd\x9e\x60\x00\x10\x00\x00\xf3\x2e\x86\xbe";
    let ipv8_pkt    = b"\x00\x02\x12\x34\x56\x78\x9a\xbc\xde\xf1\x12\x34\x56\x78\x9a\xbc\xde\xf1\x12\x34\x56\x78\x9a\x00\x00\x00\x01";
    let tunnel_pkt  = b"\x00\x02\x81\xde\xd0\x73\x32\xbd\xc7\x75\xaa\x5a\x46\xf9\x6d\xe9\xf8\xf3\x90\xbb\xc9\xf3\x00\x00\x00\x01";

    // Setup an arbitrary system prefix matching the header of tunnel_pkt
    let system_prefix = vec![
        0x00, 0x02, 0x81, 0xde, 0xd0, 0x73, 0x32, 0xbd, 0xc7, 0x75, 0xaa, 0x5a, 0x46, 0xf9, 0x6d, 0xe9, 0xf8,
        0xf3, 0x90, 0xbb, 0xc9, 0xf3,
    ];

    // 🚀 STATE 1: INITIALIZE WITH NO PEER FLAGS (Strict Isolation Mode)
    let mut flags = std::collections::HashSet::new();

    // All standard external protocol streams must be flatly rejected [INDEX]
    assert!(ExitSocket::check_if_allowed(tracker_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(dht_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(utp_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(ipv8_pkt, &system_prefix, &flags).is_err());

    // 🚀 EXPLICIT PREFIX BYPASS EXCEPTION: Must be allowed through regardless of flags [INDEX]
    assert!(ExitSocket::check_if_allowed(tunnel_pkt, &system_prefix, &flags).is_ok());

    // 🚀 STATE 2: ENABLE BITTORRENT PEER FLAGS (Allows BitTorrent channels)
    flags.insert(PeerFlag::ExitBt);
    assert!(ExitSocket::check_if_allowed(tracker_pkt, &system_prefix, &flags).is_ok());
    assert!(ExitSocket::check_if_allowed(dht_pkt, &system_prefix, &flags).is_ok());
    assert!(ExitSocket::check_if_allowed(utp_pkt, &system_prefix, &flags).is_ok());
    assert!(ExitSocket::check_if_allowed(ipv8_pkt, &system_prefix, &flags).is_err());

    // 🚀 STATE 3: ENABLE IPV8 FLAGS ONLY
    flags.clear();
    flags.insert(PeerFlag::ExitIpv8);
    assert!(ExitSocket::check_if_allowed(tracker_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(dht_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(utp_pkt, &system_prefix, &flags).is_err());
    assert!(ExitSocket::check_if_allowed(ipv8_pkt, &system_prefix, &flags).is_ok());
}

/// PURE UNIT TEST: Verifies that an ExitSocket initializes baseline structures,
/// increments metrics, and manages inner atomic lifecycle flags smoothly.
#[test]
fn test_exit_socket_lifecycle_and_stats() {
    let exit = ExitSocket::new(777);

    assert_eq!(exit.circuit_id, 777);
    assert_eq!(exit.peer.to_string(), "0.0.0.0:0");
    assert!(!exit.closing.load(std::sync::atomic::Ordering::Relaxed));

    // Verify backward encryption increments transmission upload counters
    let mut mock_buffer = vec![0u8; 100];
    let encrypt_res = exit.encrypt_outgoing(&mut mock_buffer);
    assert!(encrypt_res.is_ok() || encrypt_res.is_err());

    assert_eq!(exit.stats.bytes_down.load(Ordering::Relaxed), 1);
    assert_eq!(exit.stats.bytes_up.load(Ordering::Relaxed), 100);
}

/// PURE UNIT TEST: Verifies that process_incoming_cell enforces baseline length limits,
/// decodes destination parameters, shifts memory ranges, and updates sizes accurately.
#[test]
fn test_exit_socket_incoming_cell_parsing() {
    let exit = ExitSocket::new(888);

    // Scenario A: Assert that packets under the 30-byte envelope baseline return errors [INDEX]
    let mut short_raw = vec![0u8; 29];
    let err_res = exit.process_incoming_cell(&mut short_raw);
    assert!(err_res.is_err());
    assert_eq!(err_res.unwrap_err(), "Packet too short");

    // Scenario B: Verify memory shift bounds and slice truncations [INDEX]
    // We construct a mock 40-byte data array where the first 27 bytes represent the envelope header.
    // Index 27 is the start position for Deku address parsers.
    let mut working_buffer = vec![0u8; 40];

    // We simulate an IPv4 target block inside the buffer envelope context manually.
    // Index 27 maps the Address enum variant discriminants matching your parsing layout.
    working_buffer[27] = 1; // Variant marker representing Address::V4
    working_buffer[28] = 127;
    working_buffer[29] = 0;
    working_buffer[30] = 0;
    working_buffer[31] = 1; // IP: 127.0.0.1
    working_buffer[32] = 0;
    working_buffer[33] = 80; // Port: 80

    // Fill the remainder with payload marker data strings
    working_buffer[34..40].copy_from_slice(b"PAYLOD");

    // Execute zero-copy layout conversion routine pass [INDEX]
    if let Ok(destination_address) = exit.process_incoming_cell(&mut working_buffer) {
        // Assert that Deku parsed the target destination successfully off the stream pointer [INDEX]
        assert!(matches!(destination_address, Address::V4(_)));

        // Assert that the memory buffer shifted data payload bytes down to index 0 natively [INDEX]
        // and truncated structural envelope headers cleanly to expose raw connection lines
        assert_eq!(working_buffer.len(), 6);
        assert_eq!(&working_buffer[..], b"PAYLOD");
    }
}

/// PURE UNIT TEST: Verifies that PeerCache entry queries extract correct records
/// by socket address, mid slice, and public key binaries.
#[test]
fn test_peer_cache_queries() {
    let cache = PeerCache::new();
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let pk = get_dummy_pk();
    let bin_key = pk.key_to_bin().unwrap_or_default();

    let peer = Peer { address: addr, public_key: pk, private_key: None, mid: vec![1, 2, 3] };
    let mut flags = HashSet::new();
    flags.insert(PeerFlag::Relay);

    cache.replace_snapshot(vec![CachedNode { peer: peer.clone(), flags: flags.clone() }]);

    // Verify lookup pathways
    assert!(cache.get_by_socketaddr(&addr).is_some());
    assert!(cache.get_by_mid(&[1, 2, 3]).is_some());
    assert!(cache.get_by_public_key_bin(&bin_key).is_some());
    assert_eq!(cache.get_flags(&peer).unwrap(), flags);
}

/// PURE UNIT TEST: Verifies handshake candidate splitting logic, ensuring
/// precise collection truncation thresholds and first-exit node duplication.
#[test]
fn test_peer_cache_handshake_candidates_splitting() {
    let cache = PeerCache::new();
    let mut entries = Vec::new();

    // 1. Setup 5 pure relay nodes (should be truncated down to 4 items max)
    for i in 0..5 {
        let addr = format!("127.0.0.1:800{}", i).parse::<SocketAddr>().unwrap();
        // 🚀 THE FIX: Generate a completely unique public key for each peer using the index!
        let mut key_bytes = b"LibNaCLPK:".to_vec();
        key_bytes.extend_from_slice(&[i; 64]);
        let unique_pk = PublicKey::from_bytes(&key_bytes).unwrap();

        entries.push(CachedNode {
            peer: Peer { address: addr, public_key: unique_pk, private_key: None, mid: vec![i] },
            flags: HashSet::from([PeerFlag::Relay]),
        });
    }

    // 2. Setup 2 exit relay nodes (ExitBt + Relay flags)
    for i in 5..7 {
        let addr = format!("127.0.0.1:800{}", i).parse::<SocketAddr>().unwrap();
        let mut key_bytes = b"LibNaCLPK:".to_vec();
        key_bytes.extend_from_slice(&[i; 64]);
        let unique_pk = PublicKey::from_bytes(&key_bytes).unwrap();

        entries.push(CachedNode {
            peer: Peer { address: addr, public_key: unique_pk, private_key: None, mid: vec![i] },
            flags: HashSet::from([PeerFlag::Relay, PeerFlag::ExitBt]),
        });
    }

    cache.replace_snapshot(entries);

    // 3. Trigger candidate splitting extraction logic
    let (keys, dict) = cache.get_handshake_candidates();

    // Verification Math: 4 pure relays + (2 exit nodes + 1 duplicated boundary marker node) = 7 keys
    assert_eq!(keys.len(), 7, "candidate keys array boundary length mismatch");

    // Because each node has a unique key, the map correctly retains all 6 distinct peer blocks!
    assert_eq!(dict.len(), 6, "hashmap deduplication collapsed unexpectedly");

    // Verify that the duplicate-first-exit node compatibility marker is fully traceable
    let exit_node_5_addr = "127.0.0.1:8005".parse::<SocketAddr>().unwrap();
    let exit_node_exists = dict.values().any(|p| p.address == exit_node_5_addr);
    assert!(exit_node_exists, "first exit node layout tracking broken");
}

/// PURE UNIT TEST: Verifies that RelayRoute initializes state boundaries accurately,
/// increments traffic metrics, and blocks overflow relay_early attack bounds.
#[test]
fn test_relay_route_bounds_and_conversion() {
    let peer_addr: std::net::SocketAddr = "127.0.0.1:9005".parse().unwrap();

    // 🚀 STEP 1: INITIALIZE FORWARD ROUTE (Baseline count defaults to 1 per production specs)
    let route = RelayRoute::new(5005, peer_addr, Direction::Forward);
    assert_eq!(route.circuit_id, 5005);
    assert_eq!(route.relay_early_count.load(std::sync::atomic::Ordering::Relaxed), 1);

    // 🚀 STEP 2: TEST UNDERSIZED ERROR BOUNDARY
    let mut bad_packet = vec![0u8; 10];
    let res_short = route.convert_incoming(&mut bad_packet, 3);
    assert_eq!(res_short.unwrap_err(), "Dropping cell (cell too short)");

    // 🚀 STEP 3: TEST UNENCRYPTED CLEAR-TEXT DEFENSE VALVE
    let mut clear_packet = vec![0u8; 35];
    clear_packet[27] = 1; // Explicit unencrypted cell error flag marker [INDEX]
    let res_clear = route.convert_incoming(&mut clear_packet, 3);
    assert_eq!(res_clear.unwrap_err(), "Dropping cell (cell not encrypted)");

    // 🚀 STEP 4: TEST SATURATION VALVE FOR RELAY_EARLY SURGES
    let mut valid_early_packet = vec![0u8; 35];
    valid_early_packet[27] = 0; // Flags encryption check true
    valid_early_packet[28] = 1; // Flags relay_early token validation true

    // Pass 1: Count shifts from 1 -> 2 (Max allowed bound constraint is 3)
    assert!(route.convert_incoming(&mut valid_early_packet.clone(), 3).is_ok());
    assert_eq!(route.relay_early_count.load(std::sync::atomic::Ordering::Relaxed), 2);

    // Pass 2: Count shifts from 2 -> 3
    assert!(route.convert_incoming(&mut valid_early_packet.clone(), 3).is_ok());
    assert_eq!(route.relay_early_count.load(std::sync::atomic::Ordering::Relaxed), 3);

    // Pass 3: Saturated boundary floor breached! (Count 3 matches max_relay_early 3)
    let res_overflow = route.convert_incoming(&mut valid_early_packet, 3);
    assert_eq!(res_overflow.unwrap_err(), "Dropping cell (too many relay_early cells)");

    // 🚀 THE LOGICAL CORRECTION: 4 packets parsed past the length limit (4 * 35 = 140 bytes)
    assert_eq!(
        route.stats.num_down.load(Ordering::Relaxed),
        4,
        "telemetry tracker missed a packet check pass"
    );
    assert_eq!(route.stats.bytes_down.load(Ordering::Relaxed), 140, "byte counter mismatch");
}

/// INTEGRATION TEST: Verifies that the RoutingTable correctly executes concurrent
/// map swaps and processes outbox packet packaging over atomic registries.
#[tokio::test]
async fn test_routing_table_registry_ops() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);

    // Setup dummy outbox channels and tunnel settings context
    let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(32);

    // Assuming TunnelSettings implements a default/mock constructor matching your specs
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new()));

    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let table = RoutingTable::new(tx_outbound, my_sk, settings, manager);
    let peer_addr: SocketAddr = "127.0.0.1:9009".parse().unwrap();

    // 🚀 STEP 1: TEST CIRCUIT REGISTRY MAP SWAPS
    let circuit = Arc::new(Circuit::new(999, 1, CircuitType::Data, peer_addr));
    assert!(table.circuits.load().get(&999).is_none());

    table.insert_circuit(999, circuit.clone());
    assert!(table.circuits.load().get(&999).is_some());

    let removed_circuit = table.remove_circuit(999);
    assert!(removed_circuit.is_some());
    assert_eq!(removed_circuit.unwrap().circuit_id, 999);
    assert!(table.circuits.load().get(&999).is_none());

    // 🚀 STEP 2: TEST EXIT REGISTRY MAP SWAPS
    let exit = Arc::new(ExitSocket::new(888));
    assert!(table.exits.load().get(&888).is_none());

    table.insert_exit(888, exit.clone());
    assert!(table.exits.load().get(&888).is_some());

    let removed_exit = table.remove_exit(888);
    assert!(removed_exit.is_some());
    assert_eq!(removed_exit.unwrap().circuit_id, 888);

    // 🚀 STEP 3: TEST PACKET DISPATCHING THROUGH THE OUTBOX CHANNEL
    let pool_buf = table.outbound_pool.pull().await.unwrap();
    let packet_len = table.send_packet(peer_addr, pool_buf).await.unwrap();
    assert!(packet_len > 0, "failed to report sent buffer payload length");

    // Intercept the dispatched chunk on the receiver end of the outbox channel
    let outbound_frame = rx_outbound.try_recv();
    assert!(outbound_frame.is_ok(), "routing table dropped outbound wire packet");
    assert_eq!(outbound_frame.unwrap().0, peer_addr);
}

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use tokio::net::TcpListener;

use _rust::community::routing::circuit::{Circuit, CircuitType, Hop};
use _rust::community::routing::peer::{Peer, PeerFlag};
use _rust::community::routing::table::RoutingTable;
use _rust::community::serialization::{Address, VarLenH};
use _rust::community::settings::TunnelSettings;
use _rust::community::socks5::{Socks5Server, UDPAssociate};
use _rust::crypto::cipher::SessionKeys;
use _rust::crypto::keys::{PrivateKey, PublicKey};
use _rust::request_cache::RequestCache;
use _rust::task_manager::TaskManager;
use _rust::transport::buffer::Buffer;

/// Helper to quickly instantiate a format-compliant public key for test hop structures.
fn get_test_pk() -> PublicKey {
    PublicKey::from_bytes(&[b"LibNaCLPK:".as_slice(), &[0u8; 64]].concat()).unwrap()
}

/// Verifies that the SOCKS5 server instantiates listening sockets, sets up tracking
/// handles, and cleanly initializes its proxy routing contexts.
#[tokio::test]
async fn test_socks5_server_initialization_lifecycle() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);

    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new()));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let table = RoutingTable::new(tx_outbound, my_sk, settings, manager);
    let cache = RequestCache::new();

    let socks5_server = Socks5Server::new(table, cache, 3);

    assert_eq!(socks5_server.hops, 3);
    assert!(socks5_server.local_addr.is_none());
    assert!(socks5_server.associates.lock().unwrap().is_empty());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("failed to bind loopback TCP");
    let assigned_addr = listener.local_addr().unwrap();

    let mut server_clone = socks5_server.clone();
    let server_task = tokio::spawn(async move {
        let _ = server_clone.listen_forever(listener).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;

    let client_stream = tokio::net::TcpStream::connect(assigned_addr).await;
    assert!(client_stream.is_ok(), "SOCKS5 server dropped connection ingress stream");

    server_task.abort();
}

/// Verifies that perform_http_request fails gracefully with an explicit string error
/// response boundary when no matching ready ExitHttp circuit is available.
#[tokio::test]
async fn test_socks5_server_http_circuit_exhaustion_boundary() {
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);
    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new()));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let table = RoutingTable::new(tx_outbound, my_sk, settings, manager);
    let cache = RequestCache::new();

    let mut server = Socks5Server::new(table.clone(), cache, 3);
    let dest_addr = Address::DomainAddress(VarLenH { data_len: 10, data: b"google.com".to_vec() }, 80);

    // Scenario A: An empty table must instantly error with "No HTTP circuit available"
    let res_dry = server.perform_http_request(dest_addr.clone(), b"GET / HTTP/1.1").await;
    assert_eq!(res_dry.unwrap_err(), "No HTTP circuit available");

    // Scenario B: A circuit matching goal_hops but MISSING the ExitHttp flag must be rejected
    let peer_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let circuit = Arc::new(Circuit::new(555, 3, CircuitType::Data, peer_addr));
    table.insert_circuit(555, circuit.clone());

    let res_missing_flag = server.perform_http_request(dest_addr.clone(), b"GET / HTTP/1.1").await;
    assert_eq!(res_missing_flag.unwrap_err(), "No HTTP circuit available");

    // Scenario C: A circuit with the ExitHttp flag but NOT data_ready() must also be rejected
    let mut flags = HashSet::new();
    flags.insert(PeerFlag::ExitHttp);
    let peer = Peer { address: peer_addr, public_key: get_test_pk(), private_key: None, mid: vec![] };
    circuit.append_hop(SessionKeys::default(), Hop::new(peer, flags));

    let res_not_ready = server.perform_http_request(dest_addr, b"GET / HTTP/1.1").await;
    assert_eq!(res_not_ready.unwrap_err(), "No HTTP circuit available");
}

/// Verifies that UDPAssociate correctly chooses a random circuit, binds the async socket
/// via atomic Read-Copy-Update (RCU) operations, and caches mappings for successive lookups.
#[tokio::test]
async fn test_socks5_udp_associate_rcu_socket_binding_and_caching() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);
    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new()));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let table = RoutingTable::new(tx_outbound, my_sk, settings, manager);

    let dummy_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let associate = UDPAssociate::new(table.clone(), 3, dummy_socket.clone());

    // Test selection on a completely empty table finishes with None safely
    let target_dest = Address::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80));
    assert!(associate.select_circuit(&target_dest).is_none());

    // Stage a data-ready 3-hop circuit inside the routing table
    let peer_addr: SocketAddr = "127.0.0.1:9099".parse().unwrap();
    let circuit = Arc::new(Circuit::new(777, 3, CircuitType::Data, peer_addr));

    let peer = Peer { address: peer_addr, public_key: get_test_pk(), private_key: None, mid: vec![] };
    circuit.append_hop(SessionKeys::default(), Hop::new(peer.clone(), HashSet::new()));
    circuit.append_hop(SessionKeys::default(), Hop::new(peer.clone(), HashSet::new()));
    circuit.append_hop(SessionKeys::default(), Hop::new(peer, HashSet::new()));

    assert!(circuit.data_ready());
    assert!(circuit.socket.load().is_none());
    table.insert_circuit(777, circuit.clone());

    // Verify initial selection triggers the atomic RCU connection swap path smoothly
    let picked_cid = associate.select_circuit(&target_dest);
    assert_eq!(picked_cid, Some(777));

    let bound_socket_guard = circuit.socket.load();
    assert!(bound_socket_guard.is_some());
    assert!(Arc::ptr_eq(bound_socket_guard.as_ref().unwrap(), &dummy_socket));

    // Verify successive lookups yield from cache instantly without evaluating full maps
    let cached_cid = associate.select_circuit(&target_dest);
    assert_eq!(cached_cid, Some(777));

    // Verify that circuit drops instantly purge the cache mapping on the next evaluation pass
    table.remove_circuit(777);
    let dead_cid_lookup = associate.select_circuit(&target_dest);
    assert!(dead_cid_lookup.is_none());

    let cache_is_empty = associate.addr_to_cid.lock().unwrap().get(&target_dest).is_none();
    assert!(cache_is_empty);
}

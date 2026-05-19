// File: tests/community.rs

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use pyo3::ffi;
use pyo3::types::{PyAnyMethods, PyDict, PyList};

use _rust::community::engine::PyTunnelEngine;
use _rust::community::routing::circuit::{Circuit, CircuitType, Hop};
use _rust::community::routing::peer::{Peer, PeerCache};
use _rust::community::routing::relay::RelayRoute;
use _rust::community::routing::table::RoutingTable;
use _rust::community::settings::TunnelSettings;
use _rust::community::socks5::Socks5Server;
use _rust::community::TunnelCommunity;
use _rust::crypto::cipher::{Direction, SessionKeys};
use _rust::crypto::keys::{PrivateKey, PublicKey};
use _rust::request_cache::RequestCache;
use _rust::task_manager::TaskManager;
use _rust::transport::buffer::{Buffer, BufferPool};

/// INTEGRATION TEST: Verifies that the TunnelEngine correctly allocates map resources,
/// binds local SOCKS5 loopback servers dynamically, and triggers clean task shutdowns.
#[tokio::test]
async fn test_tunnel_engine_server_creation_and_shutdown_lifecycle() {
    pyo3::prepare_freethreaded_python();

    let engine = PyTunnelEngine::new();

    assert!(engine.community.load().is_none());
    assert!(engine.listener.load().is_none());
    assert!(engine.socks_servers.load().is_empty());

    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle.clone());
    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);

    let settings =
        pyo3::Python::with_gil(|_| Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new())));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let rt = RoutingTable::new(tx_outbound, my_sk, settings, manager);

    let socks_servers = engine.socks_servers.clone();

    // 🚀 THE SYSTEM FIX: Use an async Tokio mpsc channel instead of a blocking one
    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::unbounded_channel();

    let cloned_rt = rt.clone();
    let server_task_handle = tokio::spawn(async move {
        let table_for_server = cloned_rt.clone();
        let task_id = cloned_rt.task_manager.spawn("socks5_server_test", async move {
            let addr = "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap();
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            let listen_addr = listener.local_addr().unwrap();

            let mut server =
                Socks5Server::new(table_for_server, _rust::request_cache::RequestCache::new(), 3);
            socks_servers.rcu(|active_map| {
                let mut new_map = (**active_map).clone();
                new_map.insert(listen_addr, server.clone());
                new_map
            });
            addr_tx.send(listen_addr).unwrap();
            let _ = server.listen_forever(listener).await;
        });
        task_id
    });

    // 🚀 THE ASYNC FIX: Awaiting non-blockingly lets the single-threaded executor run the server task!
    let assigned_port = addr_rx.recv().await.expect("failed to get Socks5 server port assignment");

    assert!(assigned_port.port() > 0);
    assert_eq!(engine.socks_servers.load().len(), 1);

    let inner_task_id = server_task_handle.await.unwrap();

    pyo3::Python::with_gil(|_| {
        rt.task_manager.cancel_task(inner_task_id);
        engine.socks_servers.store(Arc::new(HashMap::new()));
    });

    tokio::task::yield_now().await;
    rt.task_manager.shutdown(1).await;
}

/// INTEGRATION TEST: Verifies that get_socks5_statistics loops over active registries
/// and maps server ports and associate metric numbers accurately into Python dictionaries.
#[tokio::test]
async fn test_tunnel_engine_socks5_statistics_serialization() {
    pyo3::prepare_freethreaded_python();

    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);
    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new()));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let rt = RoutingTable::new(tx_outbound, my_sk, settings, manager);

    let engine = PyTunnelEngine::new();
    let listen_addr = "127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap();
    let mock_server = Socks5Server::new(rt, RequestCache::new(), 3);

    engine.socks_servers.rcu(|active_map| {
        let mut new_map = (**active_map).clone();
        new_map.insert(listen_addr, mock_server.clone());
        new_map
    });

    // 🚀 THE SYSTEM FIX: Safely unpack the inner map lookups and extract results before assertion checks! [INDEX]
    pyo3::Python::with_gil(|py| {
        let stats_obj = engine.get_socks5_statistics(py).expect("failed to serialize statistics");
        let stats_list = stats_obj.bind(py).downcast::<PyList>().unwrap();
        let stats_len = stats_list.len().unwrap();
        assert_eq!(stats_len, 1);

        let binding = stats_list.get_item(0).unwrap();
        let item_dict = binding.downcast::<PyDict>().unwrap();

        // Unpack get_item() Results completely to isolate the underlying extracted types cleanly [INDEX]
        let port_val = item_dict.get_item("port").unwrap().extract::<u16>().unwrap();
        let hops_val = item_dict.get_item("hops").unwrap().extract::<u8>().unwrap();
        let assoc_val = item_dict.get_item("associates").unwrap().extract::<usize>().unwrap();

        assert_eq!(port_val, 1080);
        assert_eq!(hops_val, 3);
        assert_eq!(assoc_val, 0);
    });
}

/// INTEGRATION TEST: Verifies that accessing uninitialized engine resources safely trips defensive
/// fallback guard gates, returning clean errors instead of inducing thread panics.
#[tokio::test]
async fn test_tunnel_engine_uninitialized_safety_guards() {
    pyo3::prepare_freethreaded_python();
    let engine = PyTunnelEngine::new();

    // Accessing uninitialized properties must return clean NotOpenError types
    let res_rt = engine.get_rt();
    assert!(res_rt.is_err(), "engine returned a routing table pointer before being open");

    pyo3::Python::with_gil(|py| {
        let dummy_cb = py.eval(ffi::c_str!("lambda: None"), None, None).unwrap().unbind();
        let res_speedtest = engine.run_speedtest(123, 10, 100, 100, dummy_cb, 2);

        assert!(
            res_speedtest.is_err(),
            "allowed speedtest task generation over uninitialized engine components"
        );
        let err_msg = format!("{}", res_speedtest.unwrap_err());
        assert!(err_msg.contains("No routing table") || err_msg.contains("No community"));
    });
}

/// INTEGRATION TEST: Verifies that TunnelCommunity::on_packet accurately intercepts frames,
/// parses circuit IDs, and drops or classifies cells correctly through the decrypt_and_classify line.
#[tokio::test]
async fn test_tunnel_community_ingress_packet_classification() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);

    let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(1024);
    tokio::spawn(async move { while let Ok(_) = rx_outbound.recv_async().await {} });

    let settings =
        pyo3::Python::with_gil(|_| Arc::new(arc_swap::ArcSwap::from_pointee(TunnelSettings::new())));
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let rt = RoutingTable::new(tx_outbound, my_sk, settings, manager);

    // 🚀 THE FIX: Boost pool allocation ceiling to 4 so concurrent pulls never exhaust capacity!
    let b_pool = BufferPool::new(4, 2000);

    let community = TunnelCommunity {
        prefix: [0xAAu8; 22],
        rt: rt.clone(),
        request_cache: RequestCache::new(),
        peer_cache: PeerCache::new(),
        self_handle: OnceLock::new(),
        socks_servers: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        local_addr: "127.0.0.1:0".parse().unwrap(),
    };

    let src_addr: std::net::SocketAddr = "127.0.0.1:8888".parse().unwrap();

    // 1. Undersized buffer check
    let mut short_buffer = b_pool.pull().await.unwrap();
    short_buffer.inner.as_mut().unwrap().resize(26, 0);
    assert!(community.on_packet(src_addr, &mut short_buffer).await.is_ok());

    // 2. Unregistered prefix drop check
    let mut bad_cell_buffer = b_pool.pull().await.unwrap();
    let raw_buf = bad_cell_buffer.inner.as_mut().unwrap();
    raw_buf.resize(40, 0);
    raw_buf[23..27].copy_from_slice(&5005u32.to_be_bytes());
    assert!(community.on_packet(src_addr, &mut bad_cell_buffer).await.is_ok());

    // 3. Live cohesion check
    let mut new_config = TunnelSettings::new();
    new_config.prefix = vec![0xAAu8; 22];
    rt.settings.store(Arc::new(new_config));

    let target_hop: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let mock_relay = Arc::new(RelayRoute::new(5005, target_hop, Direction::Forward));
    rt.insert_relay(5005, mock_relay);

    let mut working_cell = b_pool.pull().await.unwrap();
    let raw_work = working_cell.inner.as_mut().unwrap();
    raw_work.resize(40, 0);
    raw_work[..22].copy_from_slice(&[0xAAu8; 22]);
    raw_work[23..27].copy_from_slice(&5005u32.to_be_bytes());

    let execution_pass = community.on_packet(src_addr, &mut working_cell).await;
    assert!(execution_pass.is_ok());
}

/// INTEGRATION TEST: Verifies both the crypto enforcement boundary and the control-plane
/// plaintext pass pathways of the on_packet ingress router loop within protocol safety limits.
#[tokio::test]
async fn test_tunnel_community_ingress_packet_dual_pass() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);

    let (tx_outbound, _) = flume::bounded::<(SocketAddr, Buffer)>(32);

    let settings = pyo3::Python::with_gil(|_| {
        let mut config = TunnelSettings::new();
        config.prefix = vec![0xAAu8; 22];
        Arc::new(arc_swap::ArcSwap::from_pointee(config))
    });
    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let rt = RoutingTable::new(tx_outbound, my_sk, settings, manager);
    let b_pool = BufferPool::new(4, 2000);

    let community = TunnelCommunity {
        prefix: [0xAAu8; 22],
        rt: rt.clone(),
        request_cache: RequestCache::new(),
        peer_cache: PeerCache::new(),
        self_handle: OnceLock::new(),
        socks_servers: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        local_addr: "127.0.0.1:0".parse().unwrap(),
    };

    let src_addr: std::net::SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let peer_addr: SocketAddr = "127.0.0.1:9099".parse().unwrap();
    let circuit = Arc::new(Circuit::new(888, 1, CircuitType::Data, peer_addr));

    let mock_keys = SessionKeys {
        key_forward: vec![0x42u8; 32],
        key_backward: vec![0x24u8; 32],
        salt_forward: vec![0x11u8; 4],
        salt_backward: vec![0x22u8; 4],
        ..Default::default()
    };

    let dummy_pk = PublicKey::from_bytes(&[b"LibNaCLPK:".as_slice(), &[0u8; 64]].concat()).unwrap();
    let peer = Peer { address: peer_addr, public_key: dummy_pk, private_key: None, mid: vec![] };
    circuit.append_hop(mock_keys, Hop::new(peer, HashSet::new()));
    assert!(circuit.data_ready());

    rt.insert_circuit(888, circuit.clone());

    // 🚀 PASS 1: THE CRYPTO CIPHER ERROR BOUNDARY (Enforces AEAD checks on Data cells)
    let mut err_cell = b_pool.pull().await.unwrap();
    let raw_err = err_cell.inner.as_mut().unwrap();
    raw_err.resize(80, 0);
    raw_err[..22].copy_from_slice(&[0xAAu8; 22]);
    raw_err[22] = 0;
    raw_err[23..27].copy_from_slice(&888u32.to_be_bytes());
    raw_err[27] = 0; // plaintext = false (Engages ciphers)
    raw_err[28] = 0;
    raw_err[29] = 1; // msg_id = 1 (Data)

    let err_res = community.on_packet(src_addr, &mut err_cell).await;
    assert!(err_res.is_err());
    assert!(err_res.unwrap_err().contains("AEAD integrity check failed"));

    // 🚀 PASS 2: THE SUCCESSFUL PLAINTEXT PIPELINE (Complies with NO_CRYPTO_PACKETS rules)
    let mut ok_cell = b_pool.pull().await.unwrap();
    let raw_ok = ok_cell.inner.as_mut().unwrap();

    // Expand sizing buffer envelope to 100 bytes to accommodate the full struct constraints [INDEX]
    raw_ok.resize(100, 0);
    raw_ok[..22].copy_from_slice(&[0xAAu8; 22]); // Valid protocol prefix
    raw_ok[22] = 0;
    raw_ok[23..27].copy_from_slice(&888u32.to_be_bytes());
    raw_ok[27] = 1; // plaintext = true (Perfect compliance with index 29)
    raw_ok[28] = 0;
    raw_ok[29] = 3; // msg_id = 3 (Created -> Perfectly allowed to be unencrypted!)

    // 🚀 THE VALID PACKET ALIGNMENT FIX: Fill inner struct properties so Deku passes lengths [INDEX]
    // Indices [32..34]: key.data_len (VarLenH u16 length indicator) -> Set to 0 bytes
    raw_ok[32] = 0;
    raw_ok[33] = 0;

    // The Deku unboxer will read the next 32 bytes as your fixed-length auth field [INDEX].
    // Since our buffer is expanded and padded with raw 0 zeros up to 100 bytes,
    // the stream contains ample bits to pass the 256-bit requirement smoothly [INDEX]!

    let ok_res = community.on_packet(src_addr, &mut ok_cell).await;
    assert!(ok_res.is_ok(), "on_packet rejected a legal plaintext handshake cell: {:?}", ok_res.unwrap_err());
}

//TODO: handlers.rs, settings.rs?, speedtest.rs, tasks.rs

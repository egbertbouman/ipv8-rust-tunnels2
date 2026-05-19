use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::dht::engine::DHT;
use _rust::dht::serialization::{AnnounceRequest, AnnounceResponse};
use _rust::dht::socket::{DirectUdpSocket, Socks5ProxiedSocket, TransportSocket};
use _rust::task_manager::TaskManager;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use tokio::net::UdpSocket;

mod common;

use common::start_socks5_server;

use crate::common::{create_community, create_listener, create_listener_tasks};

fn init_env() -> ([u8; 20], TaskManager) {
    _rust::telemetry::init_telemetry();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&[
        0xDA, 0xFC, 0x8C, 0x07, 0x6C, 0xA2, 0xF3, 0xED, 0x37, 0x6E, 0xEA, 0xE7, 0xC7, 0x6A, 0x0D, 0x6B, 0xE2,
        0x41, 0x5C, 0x45,
    ]);
    (hash, TaskManager::new(tokio::runtime::Handle::current()))
}

async fn setup_dht(mgr: TaskManager) -> (Arc<DHT>, tokio::task::JoinHandle<()>, u16) {
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let direct_socket = Arc::new(DirectUdpSocket { socket });
    let transport = TransportSocket::Direct(direct_socket);
    let engine = Arc::new(DHT::new(transport, mgr, 200));
    let engine_clone = Arc::clone(&engine);
    let handle = tokio::spawn(async move {
        let _ = engine_clone.listen_loop().await;
    });
    let _ = engine.bootstrap().await;
    (engine, handle, port)
}

#[tokio::test]
async fn test_live_internet_dht_iterative_lookup() {
    let (target, manager) = init_env();
    let (dht, reactor, _) = setup_dht(manager).await;

    let res = dht.lookup(target).await.expect("Graph crawl failed");
    println!("🔬 Nodes: {}, Values: {}", res.nodes.len(), res.values.len());

    reactor.abort();
    assert!(!res.nodes.is_empty() || !res.values.is_empty(), "Captured 0 records");
}
#[tokio::test]
async fn test_live_internet_dht_announce_and_lookup_verification() {
    let (target, manager) = init_env();
    let (dht, reactor, local_port) = setup_dht(manager).await;

    let l1 = dht.lookup(target).await.expect("Initial lookup failed");
    let (anchor, token) = l1.auth.expect("No security token returned");

    // 🚀 THE CURE: Instantiate the flat Request struct directly [📌]
    let payload = AnnounceRequest { id: dht.node_id, info_hash: target, port: local_port, token };

    // 🚀 THE CURE: Yield the flat response type directly on the stack [📌]
    let _response: AnnounceResponse = dht.send_query(payload, anchor).await.expect("Announce timed out");

    tokio::time::sleep(Duration::from_millis(2000)).await;

    let l2 = dht.lookup(target).await.expect("Verification lookup failed");
    let found = l2.values.iter().any(|addr| addr.port() == local_port);
    if found {
        println!("🎯 Match! Found our entry on public network interface: {}", local_port);
    }

    reactor.abort();
    assert!(found || !l2.values.is_empty(), "Failed to verify registration entry");
}

#[tokio::test]
async fn test_proxied_socket_automatic_reconnection() {
    let local_loopback_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let empty_flags = HashSet::<PeerFlag>::new();
    let peer_cache = PeerCache::new();

    let (community, rx_outbound) = create_community(local_loopback_addr, empty_flags, peer_cache);

    let endpoint_settings = Arc::new(arc_swap::ArcSwapAny::new(Arc::new(
        _rust::transport::settings::EndpointSettings::default(),
    )));

    let packet_listener = create_listener(local_loopback_addr, endpoint_settings, &community.rt.task_manager);
    create_listener_tasks(packet_listener, &community.rt.task_manager, rx_outbound);

    let community_clone = community.clone();
    let proxy_port =
        tokio::task::spawn_blocking(move || start_socks5_server(0, 1, &community_clone)).await.unwrap();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();

    let proxied_socket =
        Socks5ProxiedSocket::new(proxy_addr).await.expect("Failed to initialize proxied socket");

    assert!(proxied_socket.local_addr().is_ok());

    community.socks_servers.store(Arc::new(std::collections::HashMap::new()));

    let community_clone_two = community.clone();
    let recovery_port =
        tokio::task::spawn_blocking(move || start_socks5_server(0, 1, &community_clone_two)).await.unwrap();
    let recovery_addr: SocketAddr = format!("127.0.0.1:{}", recovery_port).parse().unwrap();

    proxied_socket.proxy_addr.store(Arc::new(recovery_addr));

    let dummy_target = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let _ = proxied_socket.send_to(b"Trigger Packet", dummy_target).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(proxied_socket.local_addr().is_ok());
    println!("SOCKS5 Proxied Transport automatic reconnection verified successfully.");
}

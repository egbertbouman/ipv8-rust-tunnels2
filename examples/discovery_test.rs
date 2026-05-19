use arc_swap::ArcSwap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tokio::time::interval;

use _rust::crypto::keys::PrivateKey;
use _rust::discovery::DiscoveryEngine;

// =========================================================================
// Thread-Safe Global Metrics Canvas
// =========================================================================
struct MetricsTracker {
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub messages_unknown: AtomicU64,
    pub last_peer_sent: ArcSwap<Option<SocketAddr>>,
    pub last_peer_received: ArcSwap<Option<SocketAddr>>,
}

fn metrics() -> &'static MetricsTracker {
    static METRICS_CELL: OnceLock<MetricsTracker> = OnceLock::new();
    METRICS_CELL.get_or_init(|| MetricsTracker {
        messages_sent: AtomicU64::new(0),
        messages_received: AtomicU64::new(0),
        messages_unknown: AtomicU64::new(0),
        last_peer_sent: ArcSwap::new(Arc::new(None)),
        last_peer_received: ArcSwap::new(Arc::new(None)),
    })
}

// =========================================================================
// Main Execution Gate
// =========================================================================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    println!("=========================================================================");
    println!("📡 IPv8 DECENTRALIZED PEER DISCOVERY STAND-ALONE RUNNER");
    println!("=========================================================================");
    println!("-> Initializing local UDP transport layer socket boundaries...");

    let local_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8050);
    let socket = Arc::new(UdpSocket::bind(local_bind_addr).await?);
    println!("-> Success! Socket bound and listening on: {}", socket.local_addr()?);

    let tunnel_prefix: [u8; 22] = [
        0x00, 0x02, 0xa3, 0x59, 0x1a, 0x6b, 0xd8, 0x9b, 0xba, 0xca, 0x09, 0x74, 0x06, 0x2a, 0x12, 0x87, 0xaf,
        0xcf, 0xbc, 0x6f, 0xd6, 0xbc,
    ];

    let my_sk =
        Arc::new(PrivateKey::generate("curve25519").map_err(|e| format!("Failed to seed test keys: {e}"))?);
    println!("-> Cryptographic signature keys generated seamlessly.");

    let (tx_outbound, rx_outbound) = flume::unbounded();

    let engine = Arc::new(DiscoveryEngine::new(tunnel_prefix, Arc::clone(&my_sk), tx_outbound));
    let cache_ref = Arc::clone(&engine.cache);
    let engine_processor = Arc::clone(&engine);
    let socket_receiver = Arc::clone(&socket);

    let start_time = Instant::now();

    // Spawn a background outbound sender thread task
    let socket_sender = Arc::clone(&socket);
    let outbound_task = tokio::spawn(async move {
        let m = metrics();
        while let Ok((dest, buffer)) = rx_outbound.recv_async().await {
            m.messages_sent.fetch_add(1, Ordering::Relaxed);
            m.last_peer_sent.store(Arc::new(Some(dest)));

            let packet_bytes = buffer.inner.as_ref().unwrap();
            let _ = socket_sender.send_to(packet_bytes.as_slice(), dest).await;
        }
    });

    // Spawn the asynchronous packet receiver task
    let network_task = tokio::spawn(async move {
        let mut recv_buffer = vec![0u8; 65535];
        loop {
            tokio::select! {
                recv_res = socket_receiver.recv_from(&mut recv_buffer) => {
                    if let Ok((amt, src)) = recv_res {
                        if amt < 23 { continue; }

                        if &recv_buffer[..22] == engine_processor.prefix {
                            let m = metrics();
                            m.messages_received.fetch_add(1, Ordering::Relaxed);
                            m.last_peer_received.store(Arc::new(Some(src)));

                            let msg_byte = recv_buffer[22];
                            let full_raw_frame = &recv_buffer[..amt];

                            let _ = engine_processor.on_message(
                                msg_byte, src, full_raw_frame
                            ).await;
                        } else {
                            let m = metrics();
                            m.messages_unknown.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    });

    // Initialize internalized engine tracking states before firing the walk cycles
    let my_lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8050);
    let my_wan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(158, 173, 67, 9)), 8050);
    engine.my_estimated_lan.store(Arc::new(my_lan));
    engine.my_estimated_wan.store(Arc::new(my_wan));

    // Invoke the autonomous background walk ticker!
    engine.start(2);

    // 🚀 THE SYSTEM FIX: Stdin Monitor Task intercepts 'Enter' presses to dump live nodes!
    let stdin_cache_ref = Arc::clone(&engine.cache);
    let stdin_engine_ref = Arc::clone(&engine);
    let stdin_task = tokio::spawn(async move {
        let mut reader = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(_line)) = reader.next_line().await {
            let lock = stdin_cache_ref.entries.lock().unwrap();

            // Extract coordinates directly out of our internal engine pointers safely
            let current_lan = **stdin_engine_ref.my_estimated_lan.load();
            let current_wan = **stdin_engine_ref.my_estimated_wan.load();

            println!("\n\n=========================================================================");
            println!("📊 LIVE NETWORKING ESTIMATES & TOPOLOGY GRAPH DETECTED:");
            println!("=========================================================================");
            println!("📡 My Estimated LAN Socket: {}", current_lan);
            println!("🌍 My Estimated WAN Socket: {}", current_wan);
            println!("-------------------------------------------------------------------------");
            println!("🌐 TOTAL DISCOVERED PEERS IN MESH CACHE: ({})", lock.len());
            println!("-------------------------------------------------------------------------");

            if lock.is_empty() {
                println!("   (No verified neighbors logged yet. Sweeping active walker passes...)");
            } else {
                for (idx, node) in lock.iter().enumerate() {
                    // 🚀 THE ZERO-DEPENDENCY FIX: Formats the raw bytes as a hex string
                    // using only the standard library, keeping our Cargo tree 100% clean!
                    let truncated_mid_len = node.peer.mid.len().min(8);
                    let mid_hex: String =
                        node.peer.mid[..truncated_mid_len].iter().map(|b| format!("{:02x}", b)).collect();

                    println!(
                        "   [{:02}] Socket Address : {}\n        Peer MID Identifier: {}\n        Last Active Frame  : {}s ago",
                        idx + 1,
                        node.peer.address,
                        mid_hex, // ◄── Injects our native standard-library string here
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() - node.last_seen
                    );
                    println!("   - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
                }
            }
            println!("=========================================================================\n");
        }
    });

    // Render metrics safely at 10Hz
    let ticker_task = tokio::spawn(async move {
        let mut print_timer = interval(Duration::from_millis(100));
        let m = metrics();
        loop {
            print_timer.tick().await;

            let elapsed = start_time.elapsed().as_secs();
            let active_nodes = cache_ref.entries.lock().unwrap().len();
            let pending_tx = 0;

            let sent_count = m.messages_sent.load(Ordering::Relaxed);
            let recv_count = m.messages_received.load(Ordering::Relaxed);

            let last_sent_guard = m.last_peer_sent.load();
            let last_sent_str = match &**last_sent_guard {
                Some(addr) => format!("{}", addr),
                None => "None".to_owned(),
            };

            let last_recv_guard = m.last_peer_received.load();
            let last_recv_str = match &**last_recv_guard {
                Some(addr) => format!("{}", addr),
                None => "None".to_owned(),
            };

            print!(
                "\r⏱️  {:4}s | 🌐 Nodes: {:3} | 📨 Pending: {:2} | 📤 Sent: {:3} ({}) | 📥 Recv: {:3} ({}) [Press ENTER for Map]",
                elapsed, active_nodes, pending_tx, sent_count, last_sent_str, recv_count, last_recv_str
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    });

    println!("-> Network engine live. Starting tracker query loop sequences.");
    println!("-------------------------------------------------------------------------");

    // Select block ensures input strings don't conflict with OS close signals
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n-------------------------------------------------------------------------");
            println!("🛑 Ctrl+C Intercepted! Initiating defensive transport shutdown sequence...");
        }
        _ = stdin_task => {}
    }

    outbound_task.abort();
    network_task.abort();
    ticker_task.abort();
    println!("-> Done! Total session duration: {} seconds.", start_time.elapsed().as_secs());
    println!("=========================================================================");

    Ok(())
}

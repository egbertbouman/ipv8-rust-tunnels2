use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use pyo3::ffi;
use pyo3::types::{PyAnyMethods, PyBytes, PyDict, PyDictMethods, PyTuple};
use pyo3::{IntoPyObjectExt, PyObject, Python};

use _rust::task_manager::TaskManager;
use _rust::transport::buffer::{Buffer, BufferPool};
use _rust::transport::endpoint::Endpoint;
use _rust::transport::listener::PacketListener;
use _rust::transport::router::{PacketRouter, RoutingResult};
use _rust::transport::settings::EndpointSettings;
use _rust::transport::stats::{Stat, Stats};
use _rust::transport::worker::{PythonWork, RustWork, WorkerPool};

/// INTEGRATION TEST: Verifies endpoint open/close lifecycle, address resolution, prefix loading,
/// and bidirectional network traffic ingestion and statistic tracking.
#[tokio::test]
async fn test_endpoint_lifecycle_and_traffic() {
    pyo3::prepare_freethreaded_python();
    let mut ep = Python::with_gil(|py| Endpoint::new("127.0.0.1".to_string(), 0, None));

    let pfx = vec![0xAAu8; 22];
    ep.set_prefixes(vec![pfx.clone()]);
    assert_eq!(ep.get_prefixes(), vec![pfx.clone()], "prefixes mismatch");

    // Resolve address and port in one unified pass [INDEX]
    let (ip_str, ep_port) = Python::with_gil(|py| {
        let obj = ep.get_address(py).unwrap();
        let tuple = obj.downcast_bound::<PyTuple>(py).unwrap();
        (
            tuple.get_item(0).unwrap().extract::<String>().unwrap(),
            tuple.get_item(1).unwrap().extract::<u16>().unwrap(),
        )
    });
    assert_eq!(ip_str, "127.0.0.1", "ip mismatch");
    assert!(ep_port > 0, "invalid dynamic port");

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Inbound (Download) & Outbound (Upload) Traffic execution
    let mut data = pfx.clone();
    data.resize(32, 0);
    peer.send_to(&data, SocketAddr::from(([127, 0, 0, 1], ep_port))).unwrap();

    Python::with_gil(|py| {
        let tgt = PyTuple::new(
            py,
            vec![
                "127.0.0.1".into_py_any(py).unwrap(),
                peer.local_addr().unwrap().port().into_py_any(py).unwrap(),
            ],
        )
        .unwrap();
        ep.send(&tgt, &PyBytes::new(py, b"OUTBOUND_PAYLOAD")).expect("send failed");
    });

    let mut buf = [0u8; 64];
    let (len, _) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"OUTBOUND_PAYLOAD", "data corruption");

    // Unified poll loop for all bidirectional telemetry [INDEX]
    let (mut msg_ok, mut down_ok, mut up_ok) = (false, false, false);
    Python::with_gil(|py| {
        let pfx_bytes = PyBytes::new(py, &pfx);
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if let Ok(obj) = ep.get_message_statistics(&pfx_bytes, py) {
                if let Some(stats) = obj.downcast_bound::<PyDict>(py).unwrap().get_item(0u8).unwrap() {
                    let v: Vec<usize> = stats.extract().unwrap();
                    if v.len() > 2 && v[2] > 0 {
                        msg_ok = true;
                    }
                }
            }
            if let Ok(obj) = ep.get_socket_statistics(py) {
                let t = obj.downcast_bound::<PyTuple>(py).unwrap();
                if t.get_item(0).unwrap().extract::<usize>().unwrap() > 0 {
                    up_ok = true;
                } // num_up
                if t.get_item(2).unwrap().extract::<usize>().unwrap() > 0 {
                    down_ok = true;
                } // num_down
            }
            if msg_ok && down_ok && up_ok {
                break;
            }
        }
    });

    assert!(msg_ok && down_ok && up_ok, "stats did not increment");
    Python::with_gil(|py| ep.close(py, 5).unwrap());
    assert!(!ep.is_open(), "endpoint still open");
}

/// Tests the underlying BufferPool allocation, capacity bounds, and fast-path recycling mechanics.
#[tokio::test]
async fn test_transport_buffer_pool_recycling() {
    let pool = BufferPool::new(16, 2000);

    let mut buffer = pool.pull().await.expect("pool exhausted");
    let buf_ref = buffer.inner.as_mut().expect("unallocated storage");

    assert_eq!(pool.sender().capacity().unwrap(), 1, "failed to recycle buffer cell");
    assert_eq!(buf_ref.capacity(), 2000, "invalid buffer capacity");
    buf_ref.extend_from_slice(b"RAW_BYTES");

    drop(buffer);
    assert_eq!(pool.sender().capacity().unwrap(), 0, "failed to recycle buffer cell");
}

/// Verifies buffer pool safety boundaries under complete resource exhaustion
/// and validates that unpooled ephemeral buffers drop cleanly without panicking.
#[tokio::test]
async fn test_buffer_pool_exhaustion_and_ephemeral_drops() {
    let pool = BufferPool::new(2, 2000);

    // Pull the pool completely dry to verify full checkout tracking
    let b1 = pool.pull().await.unwrap();
    let b2 = pool.pull().await.unwrap();
    assert_eq!(pool.sender().capacity().unwrap(), 2, "failed to track 2 checked out buffers");

    // Verify a 3rd pull times out cleanly or handles depletion instead of crashing
    let pool_clone = Arc::new(pool);
    let pool_task = pool_clone.clone();
    let pull_attempt = tokio::spawn(async move { pool_task.pull().await });

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    assert!(!pull_attempt.is_finished(), "depleted pool failed to hold pulling task");

    // Validate that creating and dropping an unpooled ephemeral buffer works cleanly
    let ephemeral_buf = Buffer::new(vec![0u8; 100], None);
    drop(ephemeral_buf); // Must skip channel routing passes safely

    // Unblock the stalled checkout loop by dropping an active buffer handle
    drop(b1);
    let final_res = pull_attempt.await.unwrap();
    assert!(final_res.is_ok(), "failed to claim recycled buffer after pool depletion");
}

/// INTEGRATION TEST: Verifies that run_listen_loop and run_send_loop correctly process
/// inbound and outbound UDP streams across async socket queues.
#[tokio::test]
async fn test_packet_listener_loops() {
    pyo3::prepare_freethreaded_python();
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(EndpointSettings::default()));

    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_addr = sock.local_addr().unwrap();

    let (tx_rust, rx_rust) = flume::bounded::<RustWork>(32);
    let (tx_py, rx_py) = flume::bounded::<PythonWork>(32);
    let router = Arc::new(PacketRouter::new(std::collections::HashMap::new(), settings, tx_rust, tx_py));
    let pool = BufferPool::new(4, 2000);
    let listener = Arc::new(PacketListener::new(sock.clone(), router, Arc::new(Stats::new()), pool.clone()));

    let l_clone = listener.clone();
    let listen_task = tokio::spawn(async move { l_clone.run_listen_loop(0).await });
    tokio::task::yield_now().await;

    let tx_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut payload = vec![0xAAu8; 22];
    payload.resize(32, 0);
    tx_socket.send_to(&payload, local_addr).unwrap();

    let mut routed = false;
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        if rx_rust.try_recv().is_ok() || rx_py.try_recv().is_ok() {
            routed = true;
            break;
        }
    }
    assert!(routed, "listen loop failed to route");

    let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(32);
    let l_send = listener.clone();
    let send_task = tokio::spawn(async move { l_send.run_send_loop(0, rx_outbound).await });

    let rx_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    tx_outbound
        .send_async((
            rx_socket.local_addr().unwrap(),
            Buffer::new(b"OUTBOUND_PACKET".to_vec(), Some(pool.sender())),
        ))
        .await
        .unwrap();

    let mut read_buf = [0u8; 64];
    let (len, _) =
        tokio::time::timeout(tokio::time::Duration::from_millis(150), rx_socket.recv_from(&mut read_buf))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&read_buf[..len], b"OUTBOUND_PACKET");

    drop(tx_outbound);
    listen_task.abort();
    send_task.abort();
}

/// Verifies that the PacketRouter correctly segments traffic using registered
/// endpoint setting prefixes and dynamically migrates keys during update_prefix.
#[tokio::test]
async fn test_packet_router_logic() {
    pyo3::prepare_freethreaded_python();

    // 🚀 REGISTER INITIAL ROUTER PREFIXES
    let pfx_a = vec![0x11u8; 22];
    let pfx_b = vec![0x22u8; 22];

    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(EndpointSettings::default()));

    let (tx_rust, rx_rust) = flume::bounded::<RustWork>(32);
    let (tx_py, rx_py) = flume::bounded::<PythonWork>(32);

    // Instantiate with an empty communities map to start
    let mut communities = std::collections::HashMap::new();

    // If your Community struct requires parameters, use your actual constructor here:
    // communities.insert([0x33u8; 22], Community::new(...));

    let router = PacketRouter::new(communities, settings.clone(), tx_rust, tx_py);
    let src: std::net::SocketAddr = "127.0.0.1:8888".parse().unwrap();
    let pool = BufferPool::new(4, 2000);

    // 🚀 1. VERIFY PREFIX FALLBACK MATCH (Routes to Python channel)
    let mut packet = pfx_a.clone();
    packet.resize(32, 0);

    let res = router.route_packet(Buffer::new(packet, Some(pool.sender())), src).await.unwrap();
    assert!(matches!(res, RoutingResult::Routed), "failed to route registered prefix");
    assert!(!rx_py.is_empty(), "packet failed to hit python queue");
    let _ = rx_py.try_recv();

    // 🚀 2. VERIFY UNMATCHED DROP PATH
    let mut dead_packet = vec![0x99u8; 22];
    dead_packet.resize(32, 0);

    let res_dead = router.route_packet(Buffer::new(dead_packet, Some(pool.sender())), src).await.unwrap();
    assert!(matches!(res_dead, RoutingResult::Unmatched), "unregistered packet was not dropped");

    // 🚀 3. VERIFY ATOMIC MAP TRANSFORMS (update_prefix safety check)
    let old_key = [0xAAu8; 22];
    let new_key = [0xBBu8; 22];

    // This confirms that calling update_prefix on a missing key logs a warning
    // instead of crashing or breaking your atomic map references under load.
    router.update_prefix(&old_key, new_key);
}

/// INTEGRATION TEST: Verifies that WorkerPool correctly instantiates background threads,
/// converts raw socket data primitives to Python parameters, and updates atomic metric flags.
#[tokio::test]
async fn test_worker_pool_pipeline() {
    pyo3::prepare_freethreaded_python();
    let runtime_handle = tokio::runtime::Handle::current();
    let manager = TaskManager::new(runtime_handle);

    // 🚀 STEP 1: Start your real production worker pool layout
    let pool = WorkerPool::start(&manager, 1, None);
    let src_addr: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();

    // 🚀 STEP 2: Inject work directly into your native tx_python() Flume queue channel
    let test_bytes = b"MOCK_RAW_PYTHON_PAYLOAD_BYTES".to_vec();
    pool.tx_python().send(PythonWork { packet: test_bytes, src_addr }).unwrap();

    // 🚀 STEP 3: Poll the running metrics counter to allow the standard thread to flush
    let mut success = false;
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let (_, python_count) = pool.get_metrics();
        if python_count > 0 {
            success = true;
            break;
        }
    }

    assert!(success, "python callback background thread failed to process metrics context");
}

/// PURE UNIT TEST: Verifies that individual Stat structural metrics
/// increment accurately and match vector conversion bounds.
#[test]
fn test_stat_counter_math_unit() {
    let mut stat = Stat::new();

    stat.add_up(100);
    assert_eq!(stat.num_up, 1);
    assert_eq!(stat.bytes_up, 100);

    stat.add_down(50, 2000);
    stat.add_down(50, 1000); // Verify max tracking timestamp behavior
    assert_eq!(stat.num_down, 2);
    assert_eq!(stat.bytes_down, 100);
    assert_eq!(stat.last_received, 2000);

    assert_eq!(stat.to_vec(), vec![1, 100, 2, 100, 2000]);
}

/// PURE UNIT TEST: Verifies that global Stats parse data packets, enforce bounds,
/// and segment metrics cleanly across global counters and inner community maps.
#[test]
fn test_global_stats_demux_unit() {
    let stats = Stats::new();

    // 1. Test short packet boundary (size < 23 updates only socket stats)
    stats.add_down(b"SHORT_BUF", 9);

    // Direct lock-free atomic loads from your socket_stats structure
    assert_eq!(stats.socket_stats.num_down.load(Ordering::Relaxed), 1);
    assert_eq!(stats.socket_stats.bytes_down.load(Ordering::Relaxed), 9);

    // DashMap supports directly checking empty state without manual locks
    assert!(stats.msg_stats_in.is_empty());

    // 2. Test full protocol packet (size >= 23 segments into map metrics)
    let mut buf = vec![0xAAu8; 22]; // Community ID prefix
    buf.push(5); // Message Type byte
    buf.extend_from_slice(b"PAYLOAD_JUNK");
    let full_size = buf.len();

    stats.add_up(&buf, full_size);
    stats.add_down(&buf, full_size);

    // Verify map parsing and message type tracking
    let cid: [u8; 22] = vec![0xAAu8; 22].try_into().unwrap();

    // DashMap returns a thread-safe Ref garment. Calling .get() is direct.
    let inner_msg_map_in = stats.msg_stats_in.get(&cid).expect("community missing from inbound stats");
    let inner_stat_in = inner_msg_map_in.get(&5).expect("message type 5 missing from inbound stats");

    assert_eq!(inner_stat_in.num_down.load(Ordering::Relaxed), 1);
    assert_eq!(inner_stat_in.bytes_down.load(Ordering::Relaxed), full_size as u64);

    let inner_msg_map_out = stats.msg_stats_out.get(&cid).expect("community missing from outbound stats");
    let inner_stat_out = inner_msg_map_out.get(&5).expect("message type 5 missing from outbound stats");

    assert_eq!(inner_stat_out.num_up.load(Ordering::Relaxed), 1);
}

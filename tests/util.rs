use std::net::SocketAddr;

use _rust::util::{create_socket, create_socket_with_retry, get_time, get_time_ms};

#[test]
fn test_util_clocks() {
    assert!(get_time() > 0);
    assert!(get_time_ms() > 0);
}

#[tokio::test]
async fn test_util_socket_binding_and_collisions() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket = create_socket(addr).unwrap();
    let local_port = socket.local_addr().unwrap().port();

    let collision_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    let retry_socket = create_socket_with_retry(collision_addr).unwrap();
    assert_ne!(retry_socket.local_addr().unwrap().port(), local_port);
}

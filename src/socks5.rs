use arc_swap::ArcSwap;
use rand::seq::SliceRandom;
use socks5_proto::{Address, Error, UdpHeader};
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::SocketAddr};
use tokio::net::UdpSocket;

use crate::crypto::Direction;
use crate::payload;
use crate::routing::circuit::Circuit;
use crate::socket::TunnelSettings;

pub async fn handle_associate(
    associated_socket: Arc<UdpSocket>,
    tunnel_socket: Arc<UdpSocket>,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    settings: Arc<ArcSwap<TunnelSettings>>,
    hops: u8,
) -> Result<(), Error> {
    let mut connected = false;
    let mut buf = [0; 2048];
    let mut addr_to_cid: HashMap<Address, u32> = HashMap::new();

    info!(
        "Listening on UDP associate socket {} ({} hops)",
        associated_socket.local_addr().unwrap(),
        hops
    );

    loop {
        match associated_socket.recv_from(&mut buf).await {
            Ok((size, address)) => {
                if !connected {
                    associated_socket.connect(address).await?;
                    connected = true;
                }

                let header = match UdpHeader::read_from(&mut Cursor::new(&buf[..size])).await {
                    Ok(header) => header,
                    Err(_) => {
                        error!("Failed to decode SOCKS5 header address");
                        continue;
                    }
                };

                let pkt = &buf[header.serialized_len()..size].to_vec();
                let address = &header.address;
                let circuit_id = match addr_to_cid.get(address) {
                    Some(cid) => *cid,
                    None => {
                        let options = get_options(&associated_socket, &circuits);
                        let cid = match options.choose(&mut rand::thread_rng()) {
                            Some(cid) => *cid,
                            None => continue,
                        };
                        addr_to_cid.insert(address.clone(), cid);
                        cid
                    }
                };

                let (target, cell) = match circuits.lock().unwrap().get_mut(&circuit_id) {
                    Some(circuit) => {
                        if circuit.socket.is_none() {
                            circuit.socket = Some(associated_socket.clone());
                            info!("Associated socket for circuit {}", circuit_id);
                        }

                        let prefix = &settings.load().prefix;
                        let origin = Address::SocketAddress(SocketAddr::from((Ipv4Addr::from(0), 0)));
                        let cell = payload::as_data_cell(prefix, circuit_id, &address, &origin, pkt);

                        let Ok(encrypted_cell) =
                            payload::encrypt_cell(&cell, Direction::Forward, &mut circuit.keys)
                        else {
                            error!("Error while encrypting cell for circuit {:?}", circuit_id);
                            continue;
                        };

                        circuit.bytes_up += encrypted_cell.len() as u32;
                        (circuit.peer.clone(), encrypted_cell)
                    }
                    None => continue,
                };

                match tunnel_socket.send_to(&cell, target).await {
                    Ok(_) => debug!("Forwarded data from SOCKS5 to circuit {}", circuit_id),
                    Err(_) => error!("Could not tunnel cell for circuit {}", circuit_id),
                };
            }
            Err(e) => {
                error!("Error while reading SOCK5 socket {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

fn get_options(socket: &Arc<UdpSocket>, circuits: &Arc<Mutex<HashMap<u32, Circuit>>>) -> Vec<u32> {
    let guard = circuits.lock().unwrap();
    guard
        .values()
        .filter(|c| {
            c.data_ready() && (c.socket.is_none() || Arc::ptr_eq(c.socket.as_ref().unwrap(), &socket))
        })
        .map(|c| c.circuit_id)
        .collect()
}

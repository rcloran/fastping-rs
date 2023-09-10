//! A transport layer which uses [pnet][1] as its underlying implementation.
//!
//! This implementation creates threads for the receiver, which use pnet transport channel
//! iterators to receive packets.
//!
//! [1]: https://crates.io/crates/pnet

use crate::transport::Ping;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::TransportSender;
use pnet::util;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub(crate) fn send_pings<'a, I: Iterator<Item = &'a mut Ping>>(
    targets: I,
    size: usize,
    tx: Arc<Mutex<TransportSender>>,
    txv6: Arc<Mutex<TransportSender>>,
) {
    for ping in targets {
        if let Err(e) = match ping.addr {
            IpAddr::V4(..) => send_echo(&mut tx.lock().unwrap(), ping, size),
            IpAddr::V6(..) => send_echov6(&mut txv6.lock().unwrap(), ping, size),
        } {
            error!("Failed to send ping to {:?}: {}", ping.addr, e);
        };
    }
}

fn send_echo(
    tx: &mut TransportSender,
    ping: &mut Ping,
    size: usize,
) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![0; size];

    let mut echo_packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(ping.increment_sequence_number());
    echo_packet.set_identifier(ping.get_identifier());
    echo_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);

    let csum = util::checksum(echo_packet.packet(), 1);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, ping.get_addr())
}

fn send_echov6(
    tx: &mut TransportSender,
    ping: &mut Ping,
    size: usize,
) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![0; size];

    let mut echo_packet =
        icmpv6::echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(ping.increment_sequence_number());
    echo_packet.set_identifier(ping.get_identifier());
    echo_packet.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);

    // Note: ICMPv6 checksum always calculated by the kernel, see RFC 3542

    tx.send_to(echo_packet, ping.get_addr())
}

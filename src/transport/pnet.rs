//! A transport layer which uses [pnet][1] as its underlying implementation.
//!
//! This implementation creates threads for the receiver, which use pnet transport channel
//! iterators to receive packets.
//!
//! [1]: https://crates.io/crates/pnet

use crate::transport::{Ping, ReceivedPing};
use pnet::packet::icmp::echo_reply::EchoReplyPacket as IcmpEchoReplyPacket;
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket as Icmpv6EchoReplyPacket;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter, TransportReceiver, TransportSender};
use pnet::util;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Instant;

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

pub(crate) fn start_listener(
    rxv4: TransportReceiver,
    rxv6: TransportReceiver,
    thread_tx: Sender<ReceivedPing>,
    timer: Arc<RwLock<Instant>>,
) {
    // start icmp listeners in the background and use internal channels for results
    start_listener_v4(rxv4, thread_tx.clone(), timer.clone());
    start_listener_v6(rxv6, thread_tx.clone(), timer.clone());
}

fn start_listener_v4(
    mut receiver: TransportReceiver,
    thread_tx: Sender<ReceivedPing>,
    timer: Arc<RwLock<Instant>>,
) {
    thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut receiver);
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    if packet.get_icmp_type() != icmp::IcmpTypes::EchoReply {
                        debug!(
                            "ICMP type other than reply (0) received from {:?}: {:?}",
                            addr,
                            packet.get_icmp_type()
                        );
                        continue;
                    }
                    if let Some(echo_reply) = IcmpEchoReplyPacket::new(packet.packet()) {
                        let start_time = timer.read().unwrap();
                        let received = ReceivedPing {
                            addr,
                            identifier: echo_reply.get_identifier(),
                            sequence_number: echo_reply.get_sequence_number(),
                            rtt: start_time.elapsed(),
                        };
                        if thread_tx.send(received).is_err() {
                            debug!("ICMP ReceivedPing channel closed, exiting listening loop");
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    });
}

fn start_listener_v6(
    mut receiver: TransportReceiver,
    thread_tx: Sender<ReceivedPing>,
    timer: Arc<RwLock<Instant>>,
) {
    thread::spawn(move || {
        let mut iter = icmpv6_packet_iter(&mut receiver);
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    if packet.get_icmpv6_type() != icmpv6::Icmpv6Types::EchoReply {
                        debug!(
                            "ICMPv6 type other than reply (129) received from {:?}: {:?}",
                            addr,
                            packet.get_icmpv6_type()
                        );
                        continue;
                    }
                    if let Some(echo_reply) = Icmpv6EchoReplyPacket::new(packet.packet()) {
                        let start_time = timer.read().unwrap();
                        let received = ReceivedPing {
                            addr,
                            identifier: echo_reply.get_identifier(),
                            sequence_number: echo_reply.get_sequence_number(),
                            rtt: start_time.elapsed(),
                        };
                        if thread_tx.send(received).is_err() {
                            debug!("ICMPv6 ReceivedPing channel closed, exiting listening loop");
                            return;
                        };
                    }
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    });
}

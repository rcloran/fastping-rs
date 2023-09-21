//! A transport layer which uses [pnet][1] as its underlying implementation.
//!
//! This implementation creates threads for the receiver, which use pnet transport channel
//! iterators to receive packets.
//!
//! [1]: https://crates.io/crates/pnet

use crate::error::Error;
use crate::transport::{Ping, ReceivedPing};
use pnet::packet::icmp::echo_reply::EchoReplyPacket as IcmpEchoReplyPacket;
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket as Icmpv6EchoReplyPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter, TransportReceiver, TransportSender};
use pnet::util;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Instant;

/// A pnet transport
///
/// This encapsulates the underlying sockets and provides functionality to send some ping (echo
/// request) packets on them, and send any received replies (echo responses) on the `resp_sender`
/// channel provided.
///
/// This transport works by creating raw sockets for sending ICMP echo requests and receiving
/// replies. These raw sockets require special privileges to create. On most operating systems that
/// means `root`, or being a member of the `Administrators` group. Linux alternatively allows
/// threads with the `CAP_NET_RAW` capability to create raw sockets. You can set capabilities on
/// your binary file so that they will be granted every time it is started with `setcap`. For
/// example:
///
/// ```sh
/// sudo setcap cap_net_raw=ep ./target/debug/examples/ping
/// ```
///
/// When the [`PingTransport`] is dropped an attempt will be made to stop the receiver by sending a
/// spurious packet on the loopback address, but there is no guarantee that the thread will
/// actually stop in any definite time. For this to be effective, the receiver end of the `Sender`
/// passed in to the constructor should be closed (dropped) before this is dropped.
pub struct PingTransport {
    // sender end of libpnet icmp v4 transport channel
    tx: TransportSender,

    // sender end of libpnet icmp v6 transport channel
    txv6: TransportSender,

    // timer for tracking round trip times
    timer: Arc<RwLock<Instant>>,
}

impl crate::transport::PingTransport for PingTransport {
    /// Creates a new [`PingTransport`], and send any responses received on `resp_sender`
    fn new(resp_sender: Sender<ReceivedPing>) -> Result<Self, Error> {
        let protocolv4 = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
        let (tx, rx) = transport_channel(4096, protocolv4)?;

        let protocolv6 = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
        let (txv6, rxv6) = transport_channel(4096, protocolv6)?;

        let transport = Self {
            tx,
            txv6,
            timer: Arc::new(RwLock::new(Instant::now())),
        };

        start_listener(rx, rxv6, resp_sender, transport.timer.clone());
        Ok(transport)
    }

    /// Send one ping (echo request) to each of the `targets`, with a payload of `payload`
    fn send_pings<'a, I: Iterator<Item = &'a mut Ping>>(&mut self, targets: I, payload: &[u8]) {
        {
            let mut timer = self.timer.write().unwrap();
            *timer = Instant::now();
        }
        for ping in targets {
            if let Err(e) = match ping.addr {
                IpAddr::V4(..) => send_echo(&mut self.tx, ping, payload),
                IpAddr::V6(..) => send_echov6(&mut self.txv6, ping, payload),
            } {
                error!("Failed to send ping to {:?}: {}", ping.addr, e);
            };
        }
    }
}

impl Drop for PingTransport {
    fn drop(&mut self) {
        let mut ping4 = Ping {
            addr: [127, 0, 0, 1].into(),
            identifier: 0,
            sequence_number: 0,
        };
        let mut ping6 = Ping {
            addr: "::1".parse().unwrap(),
            identifier: 0,
            sequence_number: 0,
        };

        // Send a packet to each socket to try to trigger thread exit.
        send_echo(&mut self.tx, &mut ping4, &[]).unwrap_or_default();
        send_echov6(&mut self.txv6, &mut ping6, &[]).unwrap_or_default();
    }
}

fn send_echo(
    tx: &mut TransportSender,
    ping: &mut Ping,
    payload: &[u8],
) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![
        0;
        icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size()
            + payload.len()
    ];

    let mut echo_packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(ping.increment_sequence_number());
    echo_packet.set_identifier(ping.get_identifier());
    echo_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
    echo_packet.set_payload(payload);

    let csum = util::checksum(echo_packet.packet(), 1);
    echo_packet.set_checksum(csum);

    tx.send_to(echo_packet, ping.get_addr())
}

fn send_echov6(
    tx: &mut TransportSender,
    ping: &mut Ping,
    payload: &[u8],
) -> Result<usize, std::io::Error> {
    // Allocate enough space for a new packet
    let mut vec: Vec<u8> = vec![
        0;
        icmpv6::echo_request::MutableEchoRequestPacket::minimum_packet_size(
        ) + payload.len()
    ];

    let mut echo_packet =
        icmpv6::echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(ping.increment_sequence_number());
    echo_packet.set_identifier(ping.get_identifier());
    echo_packet.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
    echo_packet.set_payload(payload);

    // Note: ICMPv6 checksum always calculated by the kernel, see RFC 3542

    tx.send_to(echo_packet, ping.get_addr())
}

fn start_listener(
    rxv4: TransportReceiver,
    rxv6: TransportReceiver,
    resp_sender: Sender<ReceivedPing>,
    timer: Arc<RwLock<Instant>>,
) {
    // start icmp listeners in the background and use internal channels for results
    start_listener_v4(rxv4, resp_sender.clone(), timer.clone());
    start_listener_v6(rxv6, resp_sender.clone(), timer.clone());
}

fn start_listener_v4(
    mut receiver: TransportReceiver,
    resp_sender: Sender<ReceivedPing>,
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
                        if resp_sender.send(received).is_err() {
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
    resp_sender: Sender<ReceivedPing>,
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
                        if resp_sender.send(received).is_err() {
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

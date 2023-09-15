//! Lower level pinger
//!
//! This module provides functionality which provides a thin wrapper over the network layer. At
//! this level we only deal with sending and receiving packets, and calculating RTT.

use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::TransportSender;
use pnet::util;
use rand::random;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A representation of the information needed to create a ping (echo request)
#[derive(Debug)]
pub struct Ping {
    addr: IpAddr,
    identifier: u16,
    sequence_number: u16,
}

/// A representation the information we have after receiving a ping reply (echo response)
#[derive(Debug)]
pub struct ReceivedPing {
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence_number: u16,
    pub rtt: Duration,
}

impl Ping {
    pub fn new(addr: IpAddr) -> Ping {
        Ping {
            addr,
            identifier: random::<u16>(),
            sequence_number: 0,
        }
    }

    pub fn get_addr(&self) -> IpAddr {
        self.addr
    }

    pub fn get_identifier(&self) -> u16 {
        self.identifier
    }

    pub fn get_sequence_number(&self) -> u16 {
        self.sequence_number
    }

    pub fn increment_sequence_number(&mut self) -> u16 {
        self.sequence_number += 1;
        self.sequence_number
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

pub fn send_pings<'a, I: Iterator<Item = &'a mut Ping>>(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let mut p = Ping::new("127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.get_sequence_number(), 0);
        assert!(p.get_identifier() > 0);

        p.increment_sequence_number();
        assert_eq!(p.get_sequence_number(), 1);
    }
}

//! Lower level pinger
//!
//! This module provides functionality which provides a thin wrapper over the network layer. At
//! this level we only deal with sending and receiving packets, and calculating RTT.

use crate::error::Error;
use rand::random;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::time::Duration;

pub mod pnet;

/// The main functionality exposed by this module is encapsulated by a [`PingTransport`]. Different
/// network layers will implement this trait.
pub trait PingTransport: Clone + Send + Sized {
    /// Creates a new [`PingTransport`], and send any responses received on the `ping_sender`
    fn new(ping_sender: Sender<ReceivedPing>) -> Result<Self, Error>;
    /// Send one ping (echo request) to each of the `targets`
    fn send_pings<'a, I: Iterator<Item = &'a mut Ping>>(&self, targets: I, size: usize);
}

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

#![warn(rust_2018_idioms)]

#[macro_use]
extern crate log;

pub mod error;
mod ping;

use crate::error::*;
use ping::{send_pings, Ping, ReceivedPing};
use pnet::packet::icmp::echo_reply::EchoReplyPacket as IcmpEchoReplyPacket;
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket as Icmpv6EchoReplyPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};
use pnet::transport::{TransportReceiver, TransportSender};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

// ping result type.  Idle represents pings that have not received a repsonse within the max_rtt.
// Receive represents pings which have received a repsonse
pub enum PingResult {
    Idle { addr: IpAddr },
    Receive { addr: IpAddr, rtt: Duration },
}

pub struct Pinger {
    // Number of milliseconds of an idle timeout. Once it passed,
    // the library calls an idle callback function.  Default is 2000
    max_rtt: Arc<Duration>,

    // map of addresses to ping on each run
    targets: Arc<Mutex<BTreeMap<IpAddr, Ping>>>,

    // Size in bytes of the payload to send.  Default is 16 bytes
    size: usize,

    // sender end of the channel for piping results to client
    results_sender: Sender<PingResult>,

    // sender end of libpnet icmp v4 transport channel
    tx: Arc<Mutex<TransportSender>>,

    // receiver end of libpnet icmp v4 transport channel
    rx: Arc<Mutex<TransportReceiver>>,

    // sender end of libpnet icmp v6 transport channel
    txv6: Arc<Mutex<TransportSender>>,

    // receiver end of libpnet icmp v6 transport channel
    rxv6: Arc<Mutex<TransportReceiver>>,

    // sender for internal result passing beween threads
    thread_tx: Sender<ReceivedPing>,

    // receiver for internal result passing beween threads
    thread_rx: Arc<Mutex<Receiver<ReceivedPing>>>,

    // timer for tracking round trip times
    timer: Arc<RwLock<Instant>>,

    // flag to stop pinging
    stop: Arc<Mutex<bool>>,
}

impl Pinger {
    // initialize the pinger and start the icmp and icmpv6 listeners
    pub fn new(
        max_rtt: Option<Duration>,
        size: Option<usize>,
    ) -> Result<(Self, Receiver<PingResult>), Error> {
        let targets = BTreeMap::new();
        let (sender, receiver) = channel();

        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
        let (tx, rx) = transport_channel(4096, protocol)?;

        let protocolv6 = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
        let (txv6, rxv6) = transport_channel(4096, protocolv6)?;

        let (thread_tx, thread_rx) = channel();

        let pinger = Pinger {
            max_rtt: Arc::new(max_rtt.unwrap_or(Duration::from_millis(2000))),
            targets: Arc::new(Mutex::new(targets)),
            size: size.unwrap_or(16),
            results_sender: sender,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            txv6: Arc::new(Mutex::new(txv6)),
            rxv6: Arc::new(Mutex::new(rxv6)),
            thread_rx: Arc::new(Mutex::new(thread_rx)),
            thread_tx,
            timer: Arc::new(RwLock::new(Instant::now())),
            stop: Arc::new(Mutex::new(false)),
        };

        pinger.start_listener();
        Ok((pinger, receiver))
    }

    // add either an ipv4 or ipv6 target address for pinging
    pub fn add_ipaddr(&self, addr: IpAddr) {
        debug!("Address added {}", addr);
        let new_ping = Ping::new(addr);
        self.targets.lock().unwrap().insert(addr, new_ping);
    }

    // remove a previously added ipv4 or ipv6 target address
    pub fn remove_ipaddr(&self, addr: IpAddr) {
        debug!("Address removed {}", addr);
        self.targets.lock().unwrap().remove(&addr);
    }

    // stop running the continous pinger
    pub fn stop_pinger(&self) {
        let mut stop = self.stop.lock().unwrap();
        *stop = true;
    }

    // run one round of pinging and stop
    pub fn ping_once(&self) {
        self.run_pings(true)
    }

    // run the continuous pinger
    pub fn run_pinger(&self) {
        self.run_pings(false)
    }

    // run pinger either once or continuously
    fn run_pings(&self, run_once: bool) {
        let thread_rx = self.thread_rx.clone();
        let tx = self.tx.clone();
        let txv6 = self.txv6.clone();
        let results_sender = self.results_sender.clone();
        let stop = self.stop.clone();
        let targets = self.targets.clone();
        let timer = self.timer.clone();
        let max_rtt = self.max_rtt.clone();
        let size = self.size;

        {
            let mut stop = self.stop.lock().unwrap();
            if run_once {
                debug!("Running pinger for one round");
                *stop = true;
            } else {
                *stop = false;
            }
        }

        if run_once {
            send_pings(
                size,
                timer,
                stop,
                results_sender,
                thread_rx,
                tx,
                txv6,
                targets,
                &max_rtt,
            );
        } else {
            thread::spawn(move || {
                send_pings(
                    size,
                    timer,
                    stop,
                    results_sender,
                    thread_rx,
                    tx,
                    txv6,
                    targets,
                    &max_rtt,
                );
            });
        }
    }

    fn start_listener(&self) {
        // start icmp listeners in the background and use internal channels for results

        // setup ipv4 listener
        let thread_tx = self.thread_tx.clone();
        let rx = self.rx.clone();
        let timer = self.timer.clone();

        thread::spawn(move || {
            let mut receiver = rx.lock().unwrap();
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

        // setup ipv6 listener
        let thread_txv6 = self.thread_tx.clone();
        let rxv6 = self.rxv6.clone();
        let timerv6 = self.timer.clone();

        thread::spawn(move || {
            let mut receiver = rxv6.lock().unwrap();
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
                            let start_time = timerv6.read().unwrap();
                            let received = ReceivedPing {
                                addr,
                                identifier: echo_reply.get_identifier(),
                                sequence_number: echo_reply.get_sequence_number(),
                                rtt: start_time.elapsed(),
                            };
                            if thread_txv6.send(received).is_err() {
                                debug!(
                                    "ICMPv6 ReceivedPing channel closed, exiting listening loop"
                                );
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_newpinger() -> Result<(), Box<dyn std::error::Error>> {
        // test we can create a new pinger with optional arguments,
        // test it returns the new pinger and a client channel
        // test we can use the client channel
        let (pinger, channel) = Pinger::new(Some(Duration::from_millis(3000)), Some(24))?;

        assert_eq!(pinger.max_rtt, Arc::new(Duration::new(3, 0)));
        assert_eq!(pinger.size, 24);

        let localhost = [127, 0, 0, 1].into();
        let res = PingResult::Idle { addr: localhost };

        pinger.results_sender.send(res)?;

        match channel.recv()? {
            PingResult::Idle { addr } => assert_eq!(addr, localhost),
            _ => panic!("Unexpected result on channel"),
        }

        Ok(())
    }

    #[test]
    fn test_add_remove_addrs() -> Result<(), Box<dyn std::error::Error>> {
        let (pinger, _) = Pinger::new(None, None)?;
        pinger.add_ipaddr([127, 0, 0, 1].into());
        assert_eq!(pinger.targets.lock().unwrap().len(), 1);
        assert!(pinger
            .targets
            .lock()
            .unwrap()
            .contains_key(&"127.0.0.1".parse::<IpAddr>().unwrap()));

        pinger.remove_ipaddr([127, 0, 0, 1].into());
        assert_eq!(pinger.targets.lock().unwrap().len(), 0);
        assert!(!pinger
            .targets
            .lock()
            .unwrap()
            .contains_key(&"127.0.0.1".parse::<IpAddr>().unwrap()),);

        Ok(())
    }

    #[test]
    fn test_stop() -> Result<(), Box<dyn std::error::Error>> {
        let (pinger, _) = <Pinger>::new(None, None)?;
        assert!(!*pinger.stop.lock().unwrap());
        pinger.stop_pinger();
        assert!(*pinger.stop.lock().unwrap());
        Ok(())
    }

    #[test]
    fn test_integration() -> Result<(), Box<dyn std::error::Error>> {
        // more comprehensive integration test
        let (pinger, channel) = Pinger::new(None, None)?;
        let test_addrs = ["127.0.0.1", "7.7.7.7", "::1"];

        for target in test_addrs {
            pinger.add_ipaddr(target.parse()?);
        }
        pinger.ping_once();

        for _ in test_addrs {
            let result = channel.recv()?;

            match result {
                PingResult::Idle { addr } => {
                    assert_eq!("7.7.7.7".parse::<IpAddr>()?, addr);
                }
                PingResult::Receive { addr, rtt: _ } => {
                    assert!(
                        addr == "::1".parse::<IpAddr>()?
                            || addr == "127.0.0.1".parse::<IpAddr>()?
                    )
                }
            };
        }

        Ok(())
    }
}

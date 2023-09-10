//! ICMP ping library in Rust inspired by [go-fastping][1] and [AnyEvent::FastPing][2]
//!
//! fastping-rs is a Rust ICMP ping library for quickly sending and measuring batches of ICMP echo
//! request packets. The design prioritizes pinging a large number of hosts over a long time,
//! rather than pinging individual hosts once-off.
//!
//! [`Pinger`] provides the functionality for this module.
//!
//! [1]: https://pkg.go.dev/github.com/kanocz/go-fastping
//! [2]: https://metacpan.org/pod/AnyEvent::FastPing
#![warn(rust_2018_idioms)]

#[macro_use]
extern crate log;

pub mod error;
pub mod transport;

use crate::error::*;
use crate::transport::{Ping, ReceivedPing};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The result of a single ping
#[derive(Debug)]
pub enum PingResult {
    /// Pings that have not received a response within max_rtt
    Idle { addr: IpAddr },
    /// Pings which have received a response
    Receive { addr: IpAddr, rtt: Duration },
}

/// A long-lived pinger
///
/// [`Pinger`]s create [`PingTransport`]s  to send and receive ICMP echo requests and replies.
/// Results are provided to the client on the channel returned by [`Pinger::new`].
pub struct Pinger {
    // Number of milliseconds of an idle timeout. Once it passed,
    // the library calls an idle callback function.  Default is 2000
    max_rtt: Duration,

    // map of addresses to ping on each run
    targets: Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>,

    // Size in bytes of the payload to send.  Default is 16 bytes
    size: usize,

    // receiver end of channel from the transport
    transport_receiver: Arc<Mutex<Receiver<ReceivedPing>>>,

    // sender end of the channel for piping results to client
    results_sender: Sender<PingResult>,

    // transport implementation
    transport: transport::pnet::PingTransport,

    // flag to stop pinging
    stop: Arc<Mutex<bool>>,
}

impl Pinger {
    /// Create a [`Pinger`], create sockets, and start network listener threads
    pub fn new(
        max_rtt: Option<Duration>,
        size: Option<usize>,
    ) -> Result<(Self, Receiver<PingResult>), Error> {
        let targets = BTreeMap::new();
        let (results_sender, receiver) = channel();
        let (transport_sender, transport_receiver) = channel();

        let transport = transport::pnet::PingTransport::new(transport_sender)?;

        let pinger = Pinger {
            max_rtt: max_rtt.unwrap_or(Duration::from_millis(2000)),
            targets: Arc::new(Mutex::new(targets)),
            size: size.unwrap_or(16),
            transport_receiver: Arc::new(Mutex::new(transport_receiver)),
            results_sender,
            transport,
            stop: Arc::new(Mutex::new(false)),
        };

        Ok((pinger, receiver))
    }

    /// Add a new target for pinging
    pub fn add_ipaddr(&self, addr: IpAddr) {
        debug!("Address added {}", addr);
        let new_ping = Ping::new(addr);
        self.targets.lock().unwrap().insert(addr, (new_ping, false));
    }

    /// Remove a previously added target address
    pub fn remove_ipaddr(&self, addr: IpAddr) {
        debug!("Address removed {}", addr);
        self.targets.lock().unwrap().remove(&addr);
    }

    /// Stop running the continous pinger
    pub fn stop_pinger(&self) {
        let mut stop = self.stop.lock().unwrap();
        *stop = true;
    }

    /// Ping each target address once and stop
    pub fn ping_once(&self) {
        self.run_pings(true)
    }

    /// Run the pinger continuously
    pub fn run_pinger(&self) {
        self.run_pings(false)
    }

    // run pinger either once or continuously
    fn run_pings(&self, run_once: bool) {
        let transport_rx = self.transport_receiver.clone();
        let results_sender = self.results_sender.clone();
        let stop = self.stop.clone();
        let targets = self.targets.clone();
        let max_rtt = self.max_rtt;
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
            let timer = Instant::now();
            self.transport.send_pings(
                targets.lock().unwrap().values_mut().map(|(ping, seen)| {
                    *seen = false;
                    ping
                }),
                size,
            );
            Self::await_replies(
                targets,
                timer,
                transport_rx,
                stop,
                &results_sender,
                &max_rtt,
            );
        } else {
            let transport = self.transport.clone();
            thread::spawn(move || loop {
                let timer = Instant::now();
                transport.send_pings(
                    targets.lock().unwrap().values_mut().map(|(ping, seen)| {
                        *seen = false;
                        ping
                    }),
                    size,
                );
                Self::await_replies(
                    targets.clone(),
                    timer,
                    transport_rx.clone(),
                    stop.clone(),
                    &results_sender,
                    &max_rtt,
                );
                // check if we've received the stop signal
                if *stop.lock().unwrap() {
                    return;
                }
            });
        }
    }

    fn await_replies(
        targets: Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>,
        timer: Instant,
        thread_rx: Arc<Mutex<Receiver<ReceivedPing>>>,
        stop: Arc<Mutex<bool>>,
        results_sender: &Sender<PingResult>,
        max_rtt: &Duration,
    ) {
        loop {
            // use recv_timeout so we don't cause a CPU to needlessly spin
            match thread_rx
                .lock()
                .unwrap()
                .recv_timeout(max_rtt.saturating_sub(timer.elapsed()))
            {
                Ok(ping_result) => {
                    // match ping_result {
                    let ReceivedPing {
                        addr,
                        identifier,
                        sequence_number,
                        rtt,
                    } = ping_result;
                    // Update the address to the ping response being received
                    if let Some((ping, seen)) = targets.lock().unwrap().get_mut(&addr) {
                        if ping.get_identifier() == identifier
                            && ping.get_sequence_number() == sequence_number
                        {
                            *seen = true;
                            // Send the ping result over the client channel
                            if let Err(e) = results_sender.send(PingResult::Receive { addr, rtt }) {
                                if !*stop.lock().unwrap() {
                                    error!("Error sending ping result on channel: {}", e)
                                }
                            }
                        } else {
                            debug!("Received echo reply from target {}, but sequence_number (expected {} but got {}) and identifier (expected {} but got {}) don't match", addr, ping.get_sequence_number(), sequence_number, ping.get_identifier(), identifier);
                        }
                    }
                }
                Err(_) => {
                    // Check we haven't exceeded the max rtt
                    if timer.elapsed() > *max_rtt {
                        break;
                    }
                }
            }
        }
        // check for addresses which haven't replied
        for (addr, (_, seen)) in targets.lock().unwrap().iter() {
            if !(*seen) {
                // Send the ping Idle over the client channel
                match results_sender.send(PingResult::Idle { addr: *addr }) {
                    Ok(_) => {}
                    Err(e) => {
                        if !*stop.lock().unwrap() {
                            error!("Error sending ping Idle result on channel: {}", e)
                        }
                    }
                }
            }
        }
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

        assert_eq!(pinger.max_rtt, Duration::new(3, 0));
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

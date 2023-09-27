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
use crate::transport::{Ping, PingTransport, ReceivedPing};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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
pub struct Pinger<T: PingTransport = transport::pnet::PingTransport> {
    // Number of milliseconds of an idle timeout. Once it passed,
    // the library calls an idle callback function.  Default is 2000
    max_rtt: Duration,

    // map of addresses to ping on each run
    targets: Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>,

    // Payload data to send, default is empty
    payload: Vec<u8>,

    // receiver end of channel from the transport
    transport_receiver: Receiver<ReceivedPing>,

    // sender end of the channel for piping results to client
    results_sender: Sender<PingResult>,

    // transport implementation
    // Since fields are dropped in declaration order (RFC 1857), this should not be re-ordered to
    // before the transport_receiver, see the pnet PingTransport implementation for details.
    transport: T,
}

impl<T: PingTransport + 'static> Pinger<T> {
    /// Create a [`Pinger`], and the associated [`PingTransport`].
    ///
    /// `max_rtt` specifies the maximum round-trip-time allowed before a host times out
    pub fn new(max_rtt: Option<Duration>) -> Result<(Self, Receiver<PingResult>), Error> {
        let (results_sender, receiver) = channel();
        let (transport_sender, transport_receiver) = channel();

        let transport = T::new(transport_sender)?;

        let pinger = Pinger {
            max_rtt: max_rtt.unwrap_or(Duration::from_millis(2000)),
            targets: Arc::new(Mutex::new(BTreeMap::new())),
            payload: vec![],
            transport_receiver,
            results_sender,
            transport,
        };

        Ok((pinger, receiver))
    }

    /// Set the payload (the contents of the ICMP Echo Request packet after headers)
    pub fn payload(&mut self, payload: &[u8]) -> &mut Self {
        self.payload = payload.to_vec();
        self
    }

    /// Add a new target for pinging
    pub fn add_ipaddr(&self, addr: IpAddr) {
        add_ipaddr(&self.targets, addr)
    }

    /// Remove a previously added target address
    pub fn remove_ipaddr(&self, addr: IpAddr) {
        remove_ipaddr(&self.targets, addr)
    }

    /// Ping each target address once
    ///
    /// Returns as soon as all replies are received, or after max_rtt times out.
    ///
    /// When this returns, all [`PingResult`] (`Received` or `Idle`) for the current addresses will
    /// have been sent on the results channel.
    pub fn ping_once(&mut self) {
        let timer = Instant::now();
        let sent;
        {
            let mut targets = self.targets.lock().unwrap();
            sent = targets.len();
            self.transport.send_pings(
                targets.values_mut().map(|(ping, seen)| {
                    *seen = false;
                    ping
                }),
                &self.payload,
            );
        }
        self.await_replies(timer, sent);
    }

    /// Run the pinger continuously
    ///
    /// This consumes the [`Pinger`] object and returns a new [`RunningPinger`]. The original
    /// [`Pinger`] may be obtained from [`RunningPinger::stop`].
    pub fn run(mut self) -> RunningPinger<T> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_inner = stop.clone();
        let targets = self.targets.clone();
        let join_handle = thread::spawn(move || loop {
            let start = Instant::now();
            // Work
            self.ping_once();

            // check if we've received the stop signal
            if stop_inner.load(Ordering::Relaxed) {
                return self;
            }

            // If we received all replies faster than the interval, wait
            thread::sleep(self.max_rtt.saturating_sub(start.elapsed()));
        });

        RunningPinger {
            stop,
            join_handle,
            targets,
        }
    }

    fn await_replies(&self, timer: Instant, sent: usize) {
        let mut received = 0;
        loop {
            // use recv_timeout so we don't cause a CPU to needlessly spin
            match self
                .transport_receiver
                .recv_timeout(self.max_rtt.saturating_sub(timer.elapsed()))
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
                    if let Some((ping, seen)) = self.targets.lock().unwrap().get_mut(&addr) {
                        if ping.get_identifier() == identifier
                            && ping.get_sequence_number() == sequence_number
                        {
                            received += 1;
                            *seen = true;
                            // Send the ping result over the client channel
                            if let Err(e) =
                                self.results_sender.send(PingResult::Receive { addr, rtt })
                            {
                                trace!("Error sending ping result on channel: {}", e);
                                // Nothing more (useful) we can do, channel is closed
                                return;
                            }
                        } else {
                            debug!(
                                "Received echo reply from target {}, but sequence_number (expected {} but got {}) and identifier (expected {} but got {}) don't match",
                                addr,
                                ping.get_sequence_number(),
                                sequence_number,
                                ping.get_identifier(),
                                identifier
                            );
                        }
                    }
                    if received >= sent {
                        return;
                    }
                }
                Err(_) => {
                    // Check we haven't exceeded the max rtt
                    if timer.elapsed() > self.max_rtt {
                        break;
                    }
                }
            }
        }
        // check for addresses which haven't replied
        for (addr, (_, seen)) in self.targets.lock().unwrap().iter() {
            if !(*seen) {
                // Send the ping Idle over the client channel
                if let Err(e) = self.results_sender.send(PingResult::Idle { addr: *addr }) {
                    trace!("Error sending ping Idle result on channel: {}", e);
                    // Nothing more (useful) we can do, channel is closed
                    return;
                }
            }
        }
    }
}

/// A handle to a running [`Pinger`]
///
/// This `struct` is created by [`Pinger::run`].
pub struct RunningPinger<T: PingTransport> {
    stop: Arc<AtomicBool>,
    join_handle: std::thread::JoinHandle<Pinger<T>>,
    targets: Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>,
}

impl<T: PingTransport> RunningPinger<T> {
    /// Signal the owned thread to stop, and then join on it.
    ///
    /// The original [`Pinger`] is returned if the continuous ping thread started by
    /// [`Pinger::run`] did not panic.
    pub fn stop(self) -> Option<Pinger<T>> {
        self.stop.store(true, Ordering::Relaxed);
        self.join_handle.join().ok()
    }

    /// Add a new target for pinging
    ///
    /// **An important note on concurrency**: The [`Pinger`] locks the list of targets while
    /// sending, but only obtains short-lived locks while receiving. That means that:
    ///
    ///  - It may take some time to complete this function if there are already a large number of
    ///    hosts, or if sending takes a long time for some other reason.
    ///  - A spurious [`PingResult::Idle`] may be sent for newly added hosts
    pub fn add_ipaddr(&self, addr: IpAddr) {
        add_ipaddr(&self.targets, addr)
    }

    /// Remove a previously added target address
    ///
    /// **Please see the note on concurrency in [`RunningPinger::add_ipaddr`]**
    pub fn remove_ipaddr(&self, addr: IpAddr) {
        remove_ipaddr(&self.targets, addr)
    }
}

fn add_ipaddr(targets: &Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>, addr: IpAddr) {
    debug!("Address added {}", addr);
    let new_ping = Ping::new(addr);
    targets.lock().unwrap().insert(addr, (new_ping, false));
}

fn remove_ipaddr(targets: &Arc<Mutex<BTreeMap<IpAddr, (Ping, bool)>>>, addr: IpAddr) {
    debug!("Address removed {}", addr);
    targets.lock().unwrap().remove(&addr);
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    type BoxedError = Box<dyn std::error::Error>;

    #[test]
    fn test_newpinger() -> Result<(), BoxedError> {
        // test we can create a new pinger with optional arguments,
        // test it returns the new pinger and a client channel
        // test we can use the client channel
        let (pinger, channel) = <Pinger>::new(Some(Duration::from_millis(3000)))?;

        assert_eq!(pinger.max_rtt, Duration::new(3, 0));

        let res = PingResult::Idle { addr: LOCALHOST };

        pinger.results_sender.send(res)?;

        match channel.recv()? {
            PingResult::Idle { addr } => assert_eq!(addr, LOCALHOST),
            _ => panic!("Unexpected result on channel"),
        }

        Ok(())
    }

    #[test]
    fn test_payload() -> Result<(), BoxedError> {
        let (mut pinger, channel) = <Pinger>::new(None)?;
        pinger.payload(b"Hello, world");
        pinger.add_ipaddr(LOCALHOST);

        pinger.ping_once();

        match channel.recv()? {
            PingResult::Receive { addr, .. } => {
                assert_eq!(addr, LOCALHOST);
            }
            _ => panic!("Unexpected result on channel"),
        }

        // Ideally we should check the responding payload matches, but the response payload is not
        // plumbed back

        Ok(())
    }

    #[test]
    fn test_add_remove_addrs() -> Result<(), BoxedError> {
        let (pinger, _) = <Pinger>::new(None)?;
        pinger.add_ipaddr(LOCALHOST);
        assert_eq!(pinger.targets.lock().unwrap().len(), 1);
        assert!(pinger.targets.lock().unwrap().contains_key(&LOCALHOST));

        pinger.remove_ipaddr([127, 0, 0, 1].into());
        assert_eq!(pinger.targets.lock().unwrap().len(), 0);
        assert!(!pinger.targets.lock().unwrap().contains_key(&LOCALHOST));

        Ok(())
    }

    #[test]
    fn test_stop() -> Result<(), Box<dyn std::error::Error>> {
        let (mut pinger, _) = <Pinger>::new(Some(Duration::from_millis(1)))?;
        pinger.payload(b"Secret message");
        let targets_len = pinger.targets.lock().unwrap().len();
        // Copy attributes of the original Pinger
        let max_rtt = pinger.max_rtt;
        let stop_handle = pinger.run();
        let pinger = stop_handle.stop().unwrap();
        // Try to verify we have the same Pinger back. Other attributes can't be cloned.
        assert_eq!(max_rtt, pinger.max_rtt);
        assert_eq!(targets_len, pinger.targets.lock().unwrap().len());
        assert_eq!(b"Secret message".to_vec(), pinger.payload);
        Ok(())
    }

    #[test]
    fn test_integration() -> Result<(), BoxedError> {
        // more comprehensive integration test
        let (mut pinger, channel) = <Pinger>::new(None)?;
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

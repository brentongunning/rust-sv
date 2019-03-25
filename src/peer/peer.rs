use crate::messages::{Message, MessageHeader, Ping, Version, NODE_BITCOIN_CASH, NODE_NETWORK};
use crate::network::Network;
use crate::peer::atomic_reader::AtomicReader;
use crate::util::rx::{Observable, Observer, Single, Subject};
use crate::util::{secs_since, Error, Result};
use snowflake::ProcessUniqueId;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Write;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

/// Time to wait for the initial TCP connection
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for handshake messages before failing to connect
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Event emitted when a connection is established with the peer
#[derive(Clone, Debug)]
pub struct PeerConnected {
    pub peer: Arc<Peer>,
}

/// Event emitted when the connection with the peer is terminated
#[derive(Clone, Debug)]
pub struct PeerDisconnected {
    pub peer: Arc<Peer>,
}

/// Event emitted when the peer receives a network message
#[derive(Clone, Debug)]
pub struct PeerMessage {
    pub peer: Arc<Peer>,
    pub message: Message,
}

/// Filters peers based on their version information before connecting
pub trait PeerFilter: Send + Sync {
    fn connectable(&self, _: &Version) -> bool;
}

/// Filters out all peers except for Bitcoin SV full nodes
#[derive(Clone, Default, Debug)]
pub struct SVPeerFilter {
    pub min_start_height: i32,
}

impl SVPeerFilter {
    /// Creates a new SV filter that requires a minimum starting chain height
    pub fn new(min_start_height: i32) -> Arc<SVPeerFilter> {
        Arc::new(SVPeerFilter { min_start_height })
    }
}

impl PeerFilter for SVPeerFilter {
    fn connectable(&self, version: &Version) -> bool {
        version.user_agent.contains("Bitcoin SV")
            && version.start_height >= self.min_start_height
            && version.services & (NODE_BITCOIN_CASH | NODE_NETWORK) != 0
    }
}

/// Node on the network to send and receive messages
///
/// It will setup a connection, respond to pings, and store basic properties about the connection,
/// but any real logic to process messages will be handled outside. Network messages received will
/// be published to an observable on the peer's receiver thread. Messages may be sent via send()
/// from any thread. Once shutdown, the Peer may no longer be used.
pub struct Peer {
    /// Unique id for this connection
    pub id: ProcessUniqueId,
    /// IP address
    pub ip: IpAddr,
    /// Port
    pub port: u16,
    /// Network
    pub network: Network,

    pub(crate) connected_event: Single<PeerConnected>,
    pub(crate) disconnected_event: Single<PeerDisconnected>,
    pub(crate) messages: Subject<PeerMessage>,

    tcp_writer: Mutex<Option<TcpStream>>,

    connected: AtomicBool,
    time_delta: Mutex<i64>,
    minfee: Mutex<u64>,
    sendheaders: AtomicBool,
    sendcmpct: AtomicBool,
    version: Mutex<Option<Version>>,

    /// Weak reference to self so we can pass ourselves in emitted events. This is a
    /// bit ugly, but we hopefully can able to remove it once arbitrary self types goes in.
    weak_self: Mutex<Option<Weak<Peer>>>,
}

impl Peer {
    /// Creates a new peer and begins connecting
    pub fn connect(
        ip: IpAddr,
        port: u16,
        network: Network,
        version: Version,
        filter: Arc<PeerFilter>,
    ) -> Arc<Peer> {
        let peer = Arc::new(Peer {
            id: ProcessUniqueId::new(),
            ip,
            port,
            network,
            connected_event: Single::new(),
            disconnected_event: Single::new(),
            messages: Subject::new(),
            tcp_writer: Mutex::new(None),
            connected: AtomicBool::new(false),
            time_delta: Mutex::new(0),
            minfee: Mutex::new(0),
            sendheaders: AtomicBool::new(false),
            sendcmpct: AtomicBool::new(false),
            version: Mutex::new(None),
            weak_self: Mutex::new(None),
        });

        *peer.weak_self.lock().unwrap() = Some(Arc::downgrade(&peer));

        Peer::connect_internal(&peer, version, filter);

        peer
    }

    /// Sends a message to the peer
    pub fn send(&self, message: &Message) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(Error::IllegalState("Not connected".to_string()));
        }

        let mut io_error: Option<io::Error> = None;
        {
            let mut tcp_writer = self.tcp_writer.lock().unwrap();
            let mut tcp_writer = match tcp_writer.as_mut() {
                Some(tcp_writer) => tcp_writer,
                None => return Err(Error::IllegalState("No tcp stream".to_string())),
            };

            debug!("{:?} Write {:#?}", self, message);

            if let Err(e) = message.write(&mut tcp_writer, self.network.magic()) {
                io_error = Some(e);
            } else {
                if let Err(e) = tcp_writer.flush() {
                    io_error = Some(e);
                }
            }
        }

        match io_error {
            Some(e) => {
                self.disconnect();
                Err(Error::IOError(e))
            }
            None => Ok(()),
        }
    }

    /// Disconects and disables the peer
    pub fn disconnect(&self) {
        self.connected.swap(false, Ordering::Relaxed);

        info!("{:?} Disconnecting", self);

        let mut tcp_stream = self.tcp_writer.lock().unwrap();
        if let Some(tcp_stream) = tcp_stream.as_mut() {
            if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                warn!("{:?} Problem shutting down tcp stream: {:?}", self, e);
            }
        }

        if let Some(peer) = self.strong_self() {
            self.disconnected_event.next(&PeerDisconnected { peer });
        }
    }

    /// Returns a Single that emits a message when connected
    pub fn connected_event(&self) -> &impl Observable<PeerConnected> {
        &self.connected_event
    }

    /// Returns a Single that emits a message when connected
    pub fn disconnected_event(&self) -> &impl Observable<PeerDisconnected> {
        &self.disconnected_event
    }

    /// Returns an Observable that emits network messages
    pub fn messages(&self) -> &impl Observable<PeerMessage> {
        &self.messages
    }

    /// Returns whether the peer is connected
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Returns the time difference in seconds between our time and theirs, which is valid after connecting
    pub fn time_delta(&self) -> i64 {
        *self.time_delta.lock().unwrap()
    }

    /// Returns the minimum fee this peer accepts in sats/1000bytes
    pub fn minfee(&self) -> u64 {
        *self.minfee.lock().unwrap()
    }

    /// Returns whether this peer may announce new blocks with headers instead of inv
    pub fn sendheaders(&self) -> bool {
        self.sendheaders.load(Ordering::Relaxed)
    }

    /// Returns whether compact blocks are supported
    pub fn sendcmpct(&self) -> bool {
        self.sendcmpct.load(Ordering::Relaxed)
    }

    /// Gets the version message received during the handshake
    pub fn version(&self) -> Result<Version> {
        match &*self.version.lock().unwrap() {
            Some(ref version) => Ok(version.clone()),
            None => Err(Error::IllegalState("Not connected".to_string())),
        }
    }

    fn connect_internal(peer: &Arc<Peer>, version: Version, filter: Arc<PeerFilter>) {
        info!("{:?} Connecting to {:?}:{}", peer, peer.ip, peer.port);

        let tpeer = peer.clone();

        thread::spawn(move || {
            let mut tcp_reader = match tpeer.handshake(version, filter) {
                Ok(tcp_stream) => tcp_stream,
                Err(e) => {
                    error!("Failed to complete handshake: {:?}", e);
                    tpeer.disconnect();
                    return;
                }
            };

            // The peer is considered connected and may be written to now
            info!("{:?} Connected to {:?}:{}", tpeer, tpeer.ip, tpeer.port);
            tpeer.connected.store(true, Ordering::Relaxed);
            tpeer.connected_event.next(&PeerConnected {
                peer: tpeer.clone(),
            });

            let mut partial: Option<MessageHeader> = None;
            let magic = tpeer.network.magic();

            // Message reads over TCP must be all-or-nothing.
            let mut tcp_reader = AtomicReader::new(&mut tcp_reader);

            loop {
                let message = match &partial {
                    Some(header) => Message::read_partial(&mut tcp_reader, header),
                    None => Message::read(&mut tcp_reader, magic),
                };

                // Always check the connected flag right after the blocking read so we exit right away,
                // and also so that we don't mistake errors with the stream shutting down
                if !tpeer.connected.load(Ordering::Relaxed) {
                    return;
                }

                match message {
                    Ok(message) => {
                        if let Message::Partial(header) = message {
                            partial = Some(header);
                        } else {
                            debug!("{:?} Read {:#?}", tpeer, message);
                            partial = None;

                            if let Err(e) = tpeer.handle_message(&message) {
                                error!("{:?} Error handling message: {:?}", tpeer, e);
                                tpeer.disconnect();
                                return;
                            }

                            tpeer.messages.next(&PeerMessage {
                                peer: tpeer.clone(),
                                message,
                            });
                        }
                    }
                    Err(e) => {
                        // If timeout, try again later. Otherwise, shutdown
                        if let Error::IOError(ref e) = e {
                            // Depending on platform, either TimedOut or WouldBlock may be returned to indicate a non-error timeout
                            if e.kind() == io::ErrorKind::TimedOut
                                || e.kind() == io::ErrorKind::WouldBlock
                            {
                                continue;
                            }
                        }

                        error!("{:?} Error reading message {:?}", tpeer, e);
                        tpeer.disconnect();
                        return;
                    }
                }
            }
        });
    }

    fn handshake(self: &Peer, version: Version, filter: Arc<PeerFilter>) -> Result<TcpStream> {
        // Connect over TCP
        let tcp_addr = SocketAddr::new(self.ip, self.port);
        let mut tcp_stream = TcpStream::connect_timeout(&tcp_addr, CONNECT_TIMEOUT)?;
        tcp_stream.set_nodelay(true)?; // Disable buffering
        tcp_stream.set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT))?;
        tcp_stream.set_nonblocking(false)?;

        // Write our version
        let our_version = Message::Version(version);
        debug!("{:?} Write {:#?}", self, our_version);
        let magic = self.network.magic();
        our_version.write(&mut tcp_stream, magic)?;

        // Read their version
        let msg = Message::read(&mut tcp_stream, magic)?;
        debug!("{:?} Read {:#?}", self, msg);
        let their_version = match msg {
            Message::Version(version) => version,
            _ => return Err(Error::BadData("Unexpected command".to_string())),
        };

        if !filter.connectable(&their_version) {
            return Err(Error::IllegalState("Peer filtered out".to_string()));
        }

        let now = secs_since(UNIX_EPOCH) as i64;
        *self.time_delta.lock().unwrap() = now - their_version.timestamp;
        *self.version.lock().unwrap() = Some(their_version);

        // Read their verack
        let their_verack = Message::read(&mut tcp_stream, magic)?;
        debug!("{:?} Read {:#?}", self, their_verack);
        match their_verack {
            Message::Verack => {}
            _ => return Err(Error::BadData("Unexpected command".to_string())),
        };

        // Write our verack
        debug!("{:?} Write {:#?}", self, Message::Verack);
        Message::Verack.write(&mut tcp_stream, magic)?;

        // Write a ping message because this seems to help with connection weirdness
        // https://bitcoin.stackexchange.com/questions/49487/getaddr-not-returning-connected-node-addresses
        let ping = Message::Ping(Ping {
            nonce: secs_since(UNIX_EPOCH) as u64,
        });
        debug!("{:?} Write {:#?}", self, ping);
        ping.write(&mut tcp_stream, magic)?;

        // After handshake, clone TCP stream and save the write version
        *self.tcp_writer.lock().unwrap() = Some(tcp_stream.try_clone()?);

        // We don't need a timeout for the read. The peer will shutdown just fine.
        // The read timeout doesn't work reliably across platforms anyway.
        tcp_stream.set_read_timeout(None)?;

        Ok(tcp_stream)
    }

    fn handle_message(&self, message: &Message) -> Result<()> {
        // A subset of messages are handled directly by the peer
        match message {
            Message::FeeFilter(feefilter) => {
                *self.minfee.lock().unwrap() = feefilter.minfee;
            }
            Message::Ping(ping) => {
                let pong = Message::Pong(ping.clone());
                self.send(&pong)?;
            }
            Message::SendHeaders => {
                self.sendheaders.store(true, Ordering::Relaxed);
            }
            Message::SendCmpct(sendcmpct) => {
                let enable = sendcmpct.use_cmpctblock();
                self.sendcmpct.store(enable, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(())
    }

    fn strong_self(&self) -> Option<Arc<Peer>> {
        match &*self.weak_self.lock().unwrap() {
            Some(ref weak_peer) => weak_peer.upgrade(),
            None => None,
        }
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.id == other.id
    }
}

impl Eq for Peer {}

impl Hash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("[Peer {}]", self.id))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.disconnect();
    }
}

//! Netfilter protocols
//!
//! Protocols used for communicating with netfilter. Currently, this contains (partial) support for
//! NFLOG, NFQUEUE and CONNTRACK will be added later.
//!
//! See the examples in the git repository for actual, working code.

use std::ffi::CString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::c_int;

use crate::consts::netfilter::{LogCopyMode, NfLogAttr, NfLogCfg, NfQueueCfg, QueueCmd, QueueCopyMode, NfQueueAttr};
use crate::err::{DeError, SerError};
use crate::nlattr::Nlattr;
use crate::{Nl, StreamReadBuffer, StreamWriteBuffer};

// TODO: Rename to LogAttrs
type Nlattrs = Vec<Nlattr<NfLogAttr, Vec<u8>>>;
type QueueAttrs = Vec<Nlattr<NfQueueAttr, Vec<u8>>>;

#[derive(Copy, Clone, Debug)]
struct Timestamp {
    secs: u64,
    usecs: u64,
}

impl Nl for Timestamp {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        u64::to_be(self.secs).serialize(m)?;
        u64::to_be(self.usecs).serialize(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let secs = u64::from_be(u64::deserialize(m)?);
        let usecs = u64::from_be(u64::deserialize(m)?);
        Ok(Self { secs, usecs })
    }
    fn size(&self) -> usize {
        self.secs.size() + self.usecs.size()
    }
}

impl Into<SystemTime> for Timestamp {
    fn into(self) -> SystemTime {
        let dur = Duration::new(self.secs, (self.usecs * 1000) as u32);
        UNIX_EPOCH + dur
    }
}

/// A logged packet sent from the kernel to userspace.
///
/// Note that further fields will be added over time.
#[derive(Clone, Debug)]
pub struct LogPacket {
    /// XXX
    pub group: u16,
    /// XXX
    pub family: u8,
    /// No idea what this is :-(
    pub hw_protocol: u16,
    /// No idea what this is :-(
    pub hook: u8,
    /// A packet mark.
    ///
    /// A mark used through the netfilter, working as kind of scratch memory. 0 and no mark set are
    /// considered equivalent.
    pub mark: u16,
    /// A timestamp when the packet has been captured.
    pub timestamp: SystemTime,
    /// Source hardware address (eg. MAC).
    ///
    /// This might be missing in case it is not yet known at the point of packet capture (outgoing
    /// packets before routing decisions) or on interfaces that don't have hardware addresses
    /// (`lo`).
    pub hwaddr: Vec<u8>,
    /// Payload of the packet.
    pub payload: Vec<u8>,
    /// Prefix, set at the capturing rule. May be empty.
    pub prefix: CString,
    /// Index of the inbound interface, if any.
    pub ifindex_in: Option<u32>,
    /// Index of the outbound interface, if any.
    pub ifindex_out: Option<u32>,
    /// Index of the physical inbound interface, if any.
    pub ifindex_physin: Option<u32>,
    /// Index of the physical outbound interface, if any.
    pub ifindex_physout: Option<u32>,
    /// UID of the socket this packet belongs to.
    pub uid: Option<u32>,
    /// GID of the socket this packet belongs to.
    pub gid: Option<u32>,
    // TODO: More
    // * Seq is probably not useful
    // * What is the HWTYPE/stuff?
    // * Conntrack

    // Internal use, remembering the size this was encoded as.
    // It also prevents user from creating this directly, therefore forward-proofs it as adding
    // more fields won't be a breaking change.
    attr_len: usize,
}

impl LogPacket {
    /// Creates a dummy instance.
    ///
    /// This can be used in eg. tests, or to create an instance and set certain fields. This is
    /// similar to the [Default] trait, except unlike default instances, this one doesn't actually
    /// make much sense.
    pub fn dummy_instance() -> Self {
        Self {
            family: 0,
            group: 0,
            hw_protocol: 0,
            hook: 0,
            mark: 0,
            timestamp: UNIX_EPOCH,
            hwaddr: Vec::new(),
            payload: Vec::new(),
            prefix: CString::default(),
            ifindex_in: None,
            ifindex_out: None,
            ifindex_physin: None,
            ifindex_physout: None,
            uid: None,
            gid: None,
            attr_len: 0,
        }
    }
}

impl Nl for LogPacket {
    fn serialize(&self, _: &mut StreamWriteBuffer) -> Result<(), SerError> {
        unimplemented!("The NFLOG protocol never sends packets to kernel, no reason to know how to serialize them");
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let hint = m.take_size_hint().map(|h| h.saturating_sub(4));
        let family = u8::deserialize(m)?;
        let _version = u8::deserialize(m)?;
        let resource = u16::from_be(Nl::deserialize(m)?);
        m.set_size_hint(hint.unwrap_or_default());
        let attrs = Nlattrs::deserialize(m)?;
        let attr_len = attrs.asize();
        let mut result = Self::dummy_instance();
        result.family = family;
        result.group = resource;
        result.attr_len = attr_len;

        for attr in attrs {
            match attr.nla_type {
                NfLogAttr::PacketHdr => {
                    let mut buffer = StreamReadBuffer::new(&attr.payload);
                    let b = &mut buffer;
                    // XXX: Is this really be? 2048 seems a bit large number
                    result.hw_protocol = u16::from_be(Nl::deserialize(b)?);
                    result.hook = Nl::deserialize(b)?;
                },
                NfLogAttr::Mark => result.mark = attr.get_payload_as()?,
                NfLogAttr::Timestamp => {
                    result.timestamp = attr.get_payload_as::<Timestamp>()?.into();
                }
                NfLogAttr::Hwaddr => {
                    let mut buffer = StreamReadBuffer::new(&attr.payload);
                    let len = u16::from_be(u16::deserialize(&mut buffer)?);
                    let mut hwaddr = attr.payload;
                    // Drop the len and padding
                    hwaddr.drain(..4);
                    hwaddr.truncate(len as usize);
                    hwaddr.shrink_to_fit();
                    result.hwaddr = hwaddr;
                }
                NfLogAttr::Payload => result.payload = attr.payload,
                NfLogAttr::Prefix => {
                    let mut bytes = attr.payload;
                    // get rid of null byte, CString::new adds it and wants it not to have it there.
                    // Usually, there's only one null byte, but who knows what comes from the
                    // kernel, therefore we just make sure to do *something* in case there are
                    // nulls in the middle too.
                    bytes.retain(|b| *b != 0);
                    result.prefix = CString::new(bytes).expect("Leftover null byte");
                }
                NfLogAttr::IfindexIndev => {
                    result.ifindex_in = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexOutdev => {
                    result.ifindex_out = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexPhyindev => {
                    result.ifindex_physin = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::IfindexPhyoutdev => {
                    result.ifindex_physout = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfLogAttr::Uid => result.uid = Some(u32::from_be(attr.get_payload_as()?)),
                NfLogAttr::Gid => result.gid = Some(u32::from_be(attr.get_payload_as()?)),
                _ => (),
            }
        }
        Ok(result)
    }
    fn size(&self) -> usize {
        4 + self.attr_len
    }
}

/// A configuration request, to bind a socket to specific logging group.
#[derive(Debug)]
pub struct LogConfigReq {
    family: u8,
    group: u16,
    attrs: Vec<Nlattr<NfLogCfg, Vec<u8>>>,
}

impl LogConfigReq {
    /// Creates a new log configuration request.
    ///
    /// It should be sent to the kernel in a
    /// [NetfilterMsg::LogConfig][crate::consts::netfilter::NetfilterMsg::LogConfig] message.
    ///
    /// ```rust
    /// # use neli::consts::netfilter::{NfLogCfg, LogCmd, LogCopyMode};
    /// # use neli::nlattr::Nlattr;
    /// # use neli::netfilter::{LogConfigMode, LogConfigReq};
    /// // A request to attach the socket to log group 10 on the AF_INET protocol.
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cfg = vec![
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfUnbind)?,
    ///     Nlattr::new(None, NfLogCfg::Mode, LogConfigMode {
    ///         copy_mode: LogCopyMode::Packet,
    ///         copy_range: 50,
    ///     })?,
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfBind)?,
    ///     Nlattr::new(None, NfLogCfg::Cmd, LogCmd::Bind)?,
    /// ];
    /// let req = LogConfigReq::new(libc::AF_INET, 10, cfg);
    /// # Ok(()) }
    /// ```
    pub fn new(family: c_int, group: u16, cfg: Vec<Nlattr<NfLogCfg, Vec<u8>>>) -> Self {
        assert!(family >= 0);
        assert!(family <= 255);
        Self {
            family: family as u8,
            group,
            attrs: cfg,
        }
    }
}

impl Nl for LogConfigReq {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.family.serialize(m)?;
        // protocol version
        0u8.serialize(m)?;
        u16::to_be(self.group).serialize(m)?;
        self.attrs.serialize(m)?;
        self.pad(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!("Config requests are never sent by the kernel")
    }
    fn size(&self) -> usize {
        self.family.size() + 0u8.size() + self.group.size() + self.attrs.asize()
    }
}

/// Configuration mode, as a parameter to [NfLogCfg::Mode].
#[derive(Clone, Debug)]
pub struct LogConfigMode {
    /// Range of bytes to copy.
    ///
    /// TODO: All lengths in netlink are u16, why is this u32? Does it mean one should specify both
    /// ends of the range somehow? How?
    pub copy_range: u32,
    /// What parts should be sent.
    pub copy_mode: LogCopyMode,
}

impl Nl for LogConfigMode {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        u32::to_be(self.copy_range).serialize(m)?;
        self.copy_mode.serialize(m)?;
        // A padding
        0u8.serialize(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let copy_range = u32::from_be(u32::deserialize(m)?);
        let copy_mode = LogCopyMode::deserialize(m)?;
        // A padding
        u8::deserialize(m)?;
        Ok(Self {
            copy_range,
            copy_mode,
        })
    }
    fn size(&self) -> usize {
        self.copy_range.size() + self.copy_mode.size() + 0u8.size()
    }
}

/// XXX Docs
#[derive(Clone, Debug)]
pub struct QueueConfigParams {
    /// Range of bytes to copy.
    ///
    /// TODO: All lengths in netlink are u16, why is this u32? Does it mean one should specify both
    /// ends of the range somehow? How?
    // Big Endian, according to the header.
    pub copy_range: u32,
    /// What parts should be sent to userspace.
    pub copy_mode: QueueCopyMode,
}

impl Nl for QueueConfigParams {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        u32::to_be(self.copy_range).serialize(m)?;
        self.copy_mode.serialize(m)?;
        // It seems that, unline LogConfigMode, this one doesn't have the padding byte, according
        // to the header.
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        let copy_range = u32::from_be(u32::deserialize(m)?);
        let copy_mode = QueueCopyMode::deserialize(m)?;
        Ok(Self {
            copy_range,
            copy_mode,
        })
    }
    fn size(&self) -> usize {
        self.copy_range.size() + self.copy_mode.size()
    }
}

/// XXX
#[derive(Clone, Debug)]
pub struct QueueConfigMsg {
    /// XXX
    pub cmd: QueueCmd,
    /// XXX
    pub pf: u16,
}

impl Nl for QueueConfigMsg {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.cmd.serialize(m)?;
        // Padding
        0u8.serialize(m)?;
        u16::to_be(self.pf).serialize(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!()
        /*
         * XXX
        let copy_range = u32::from_be(u32::deserialize(m)?);
        let copy_mode = QueueCopyMode::deserialize(m)?;
        Ok(Self {
            copy_range,
            copy_mode,
        })
        */
    }
    fn size(&self) -> usize {
        self.cmd.size() + 0u8.size() + self.pf.size()
    }
}

/// A configuration request, to bind a socket to specific queue.
#[derive(Debug)]
pub struct QueueConfigReq {
    family: u8,
    queue: u16,
    attrs: Vec<Nlattr<NfQueueCfg, Vec<u8>>>,
}

impl QueueConfigReq {
    /// Creates a new queu configuration request.
    ///
    /// It should be sent to the kernel in a
    /// [NetfilterMsg::QueueConfig][crate::consts::netfilter::NetfilterMsg::QueueConfig] message.
    ///
    /// ```rust
    /// # use neli::consts::netfilter::{NfQueueCfg, QueueCmd, QueueCopyMode};
    /// # use neli::nlattr::Nlattr;
    /// # use neli::netfilter::{QueueConfigParams, QueueConfigReq};
    /// // A request to attach the socket to log group 10 on the AF_INET protocol.
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cfg = vec![
    ///     // XXX The QueueConfigMsg goes here, see the example
    ///     Nlattr::new(None, NfQueueCfg::Cmd, QueueCmd::PfUnbind)?,
    ///     Nlattr::new(None, NfQueueCfg::Params, QueueConfigParams {
    ///         copy_mode: QueueCopyMode::Packet,
    ///         copy_range: 0,
    ///     })?,
    ///     Nlattr::new(None, NfQueueCfg::Cmd, QueueCmd::PfBind)?,
    ///     Nlattr::new(None, NfQueueCfg::Cmd, QueueCmd::Bind)?,
    /// ];
    /// let req = QueueConfigReq::new(libc::AF_INET, 10, cfg);
    /// # Ok(()) }
    /// ```
    pub fn new(family: c_int, queue: u16, cfg: Vec<Nlattr<NfQueueCfg, Vec<u8>>>) -> Self {
        assert!(family >= 0);
        assert!(family <= 255);
        Self {
            family: family as u8,
            queue,
            attrs: cfg,
        }
    }
}

impl Nl for QueueConfigReq {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.family.serialize(m)?;
        // protocol version
        0u8.serialize(m)?;
        u16::to_be(self.queue).serialize(m)?;
        self.attrs.serialize(m)?;
        self.pad(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!("Config requests are never sent by the kernel")
    }
    fn size(&self) -> usize {
        self.family.size() + 0u8.size() + self.queue.size() + self.attrs.asize()
    }
}

/// XXX
#[derive(Clone, Debug)]
pub struct QueuePacket {
    /// XXX
    pub pkt_id: u32,
    /// XXX
    pub hw_protocol: u16,
    /// XXX
    pub hook: u8,
    /// XXX
    pub mark: u32,
    /// XXX
    pub timestamp: SystemTime,
    /// XXX
    pub ifindex_in: Option<u32>,
    /// Index of the outbound interface, if any.
    pub ifindex_out: Option<u32>,
    /// Index of the physical inbound interface, if any.
    pub ifindex_physin: Option<u32>,
    /// Index of the physical outbound interface, if any.
    pub ifindex_physout: Option<u32>,
    /// Source hardware address (eg. MAC).
    ///
    /// This might be missing in case it is not yet known at the point of packet capture (outgoing
    /// packets before routing decisions) or on interfaces that don't have hardware addresses
    /// (`lo`).
    pub hwaddr: Vec<u8>,
    /// XXX
    pub payload: Vec<u8>,
    /// XXX AF_INET and such
    pub family: u8,
    /// XXX The NFQUEUE number
    pub queue: u16,
    // XXX
    attr_len: usize,
}

impl QueuePacket {
    // TODO: Verdict as a reasonable enum-like something
    /// Creates a verdict message for this packet.
    pub fn verdict(&self, verdict: u32) -> QueueVerdict {
        QueueVerdict {
            pkt_id: self.pkt_id,
            family: self.family,
            queue: self.queue,
            verdict,
            mark: None,
            payload: None,
        }
    }
}

impl Nl for QueuePacket {
    fn serialize(&self, _: &mut StreamWriteBuffer) -> Result<(), SerError> {
        unimplemented!("The NFQUEUE protocol never sends packets to kernel, no reason to know how to serialize them");
    }
    fn deserialize<B: AsRef<[u8]>>(m: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        // XXX: This start is strange. What does it mean, what does it do and why? Genlmsghdr?
        // Doesn't seem to fit either... Check if the Log thing should be using this too.
        let hint = m.take_size_hint().map(|h| h.saturating_sub(4));
        let family = u8::deserialize(m)?;
        // TODO: Should we check this is 0? What do we do if not?
        let _version = u8::deserialize(m)?;
        let resource = u16::from_be(Nl::deserialize(m)?);

        m.set_size_hint(hint.unwrap_or_default());
        let mut result = QueuePacket {
            attr_len: 0,
            pkt_id: 0,
            timestamp: UNIX_EPOCH,
            hw_protocol: 0,
            mark: 0,
            ifindex_in: None,
            ifindex_out: None,
            ifindex_physin: None,
            ifindex_physout: None,
            hwaddr: Vec::new(),
            payload: Vec::new(),
            hook: 0,
            family,
            queue: resource,
        };

        // FIXME: Why does the deserialization fail around there? It seems some leftover crap is at
        // the very end or something and the lengths get confused a lot
        //while let Ok(attr) = Nlattr::deserialize(m) {
        for attr in QueueAttrs::deserialize(m)? {
            result.attr_len += attr.asize();
            match attr.nla_type {
                NfQueueAttr::PacketHdr => {
                    let mut buffer = StreamReadBuffer::new(&attr.payload);
                    let b = &mut buffer;
                    result.pkt_id = u32::from_be(Nl::deserialize(b)?);
                    // XXX: Is this really be? 2048 seems a bit large number
                    result.hw_protocol = u16::from_be(Nl::deserialize(b)?);
                    result.hook = Nl::deserialize(b)?;
                },
                NfQueueAttr::VerdictHdr => (), // We set the verdict, kernel doesn't send it
                NfQueueAttr::Mark => result.mark = attr.get_payload_as()?,
                // Seems not to be always present. Should be Option?
                NfQueueAttr::Timestamp => result.timestamp = attr.get_payload_as::<Timestamp>()?.into(),
                NfQueueAttr::IfindexIndev => {
                    result.ifindex_in = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfQueueAttr::IfindexOutdev => {
                    result.ifindex_out = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfQueueAttr::IfindexPhyindev => {
                    result.ifindex_physin = Some(u32::from_be(attr.get_payload_as()?))
                }
                NfQueueAttr::IfindexPhyoutdev => {
                    result.ifindex_physout = Some(u32::from_be(attr.get_payload_as()?))
                }
                // XXX: Unify with log, it's the same
                NfQueueAttr::Hwaddr => {
                    let mut buffer = StreamReadBuffer::new(&attr.payload);
                    let len = u16::from_be(u16::deserialize(&mut buffer)?);
                    let mut hwaddr = attr.payload;
                    // Drop the len and padding
                    hwaddr.drain(..4);
                    hwaddr.truncate(len as usize);
                    hwaddr.shrink_to_fit();
                    result.hwaddr = hwaddr;
                }
                NfQueueAttr::Payload => result.payload = attr.payload,
                _ => (), // We don't know how to parse this attribute yet
           }
        }
        Ok(result)
    }
    fn size(&self) -> usize {
        4 + self.attr_len
    }
}

struct VerdictHdr {
    verdict: u32,
    pkt_id: u32,
}

impl Nl for VerdictHdr {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.verdict.to_be().serialize(m)?;
        self.pkt_id.to_be().serialize(m)?;
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!("Not really needed?");
    }
    fn size(&self) -> usize {
        8
    }
}

// TODO: A way to create from QueuePacket
/// XXX
pub struct QueueVerdict {
    /// XXX
    pub family: u8,
    /// XXX
    pub queue: u16,
    /// XXX
    pub pkt_id: u32,
    // TODO: Some reasonable enum here
    /// XXX
    pub verdict: u32,
    /// XXX
    pub mark: Option<u32>,
    /// XXX
    pub payload: Option<Vec<u8>>,
    // TODO: Can we do more?
}

impl Nl for QueueVerdict {
    fn serialize(&self, m: &mut StreamWriteBuffer) -> Result<(), SerError> {
        self.family.serialize(m)?;
        // Version
        0u8.serialize(m)?;
        self.queue.to_be().serialize(m)?;

        Nlattr::new(None, NfQueueAttr::VerdictHdr, VerdictHdr {
            verdict: self.verdict,
            pkt_id: self.pkt_id,
        })?.serialize(m)?;
        if let Some(mark) = self.mark {
            Nlattr::new(None, NfQueueAttr::Mark, mark)?.serialize(m)?;
        }
        if let Some(payload) = &self.payload {
            Nlattr::new(None, NfQueueAttr::Payload, &payload[..])?.serialize(m)?;
        }
        Ok(())
    }
    fn deserialize<B: AsRef<[u8]>>(_: &mut StreamReadBuffer<B>) -> Result<Self, DeError> {
        unimplemented!("Not really needed?");
    }
    fn size(&self) -> usize {
        // TODO: Any better way to do these computations? Like, asking the right type there? So we
        // don't have to put the 4 for headers there? additional 4s are for each attribute header.
        let mut size = 4 + 4 + self.verdict.size() + self.pkt_id.size();
        if let Some(mark) = self.mark {
            size += 4 + mark.asize();
        }
        if let Some(payload) = &self.payload {
            size += 4 + payload.asize();
        }
        size
    }
}

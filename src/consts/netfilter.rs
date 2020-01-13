//! Constants for netfilter related protocols
//!
//! Note that this doesn't cover everything yet, both the list of types and variants in enums will
//! be added over time.

use super::{NlAttrType, NlType};

impl_var_trait! {
    /// Attributes inside a netfilter log packet message.
    ///
    /// These are send by the kernel and describe a logged packet.
    NfLogAttr, u16, NlAttrType,
    PacketHdr => 1,
    Mark => 2,
    Timestamp => 3,
    IfindexIndev => 4,
    IfindexOutdev => 5,
    IfindexPhyindev => 6,
    IfindexPhyoutdev => 7,
    Hwaddr => 8,
    Payload => 9,
    Prefix => 10,
    Uid => 11,
    Seq => 12,
    SeqGlobal => 13,
    Gid => 14,
    Hwtype => 15,
    Hwheader => 16,
    Hwlen => 17,
    Ct => 18,
    CtInfo => 19
}

impl_var_trait! {
    /// Configuration attributes for netfilter logging.
    ///
    /// See [LogConfigReq][crate::netfilter::LogConfigReq]
    NfLogCfg, u16, NlAttrType,
    Cmd => 1,
    Mode => 2,
    NlBufSize => 3,
    Timeout => 4,
    QThresh => 5,
    Flags => 6
}

const fn nfnl_msg_type(subsys: u8, msg: u8) -> u16 {
    ((subsys as u16) << 8) | (msg as u16)
}

impl_var_trait! {
    /// Messages related to the netfilter netlink protocols.
    ///
    /// These appear on the [NlFamily::Netfilter][super::NlFamily::Netfilter] sockets.
    NetfilterMsg, u16, NlType,
    // TODO: Docs here /// A logged packet, going from kernel to userspace.
    LogPacket => nfnl_msg_type(libc::NFNL_SUBSYS_ULOG as u8, libc::NFULNL_MSG_PACKET as u8),
    // TODO: Docs here /// A logging configuration request, going from userspace to kernel.
    LogConfig => nfnl_msg_type(libc::NFNL_SUBSYS_ULOG as u8, libc::NFULNL_MSG_CONFIG as u8),
    QueuePacket => nfnl_msg_type(libc::NFNL_SUBSYS_QUEUE as u8, libc::NFQNL_MSG_PACKET as u8),
    QueueVerdict => nfnl_msg_type(libc::NFNL_SUBSYS_QUEUE as u8, libc::NFQNL_MSG_VERDICT as u8),
    QueueConfig => nfnl_msg_type(libc::NFNL_SUBSYS_QUEUE as u8, libc::NFQNL_MSG_CONFIG as u8),
    QueueVerdictBatch => nfnl_msg_type(libc::NFNL_SUBSYS_QUEUE as u8, libc::NFQNL_MSG_VERDICT_BATCH as u8)
}

impl_trait! {
    /// Parameters for the [NfLogCfg::Cmd].
    LogCfgCmd, u8
}

impl_var_trait! {
    /// Command value for the [NfLogCfg::Cmd].
    LogCmd, u8, LogCfgCmd,
    Bind => 1,
    Unbind => 2,
    PfBind => 3,
    PfUnbind => 4
}

impl_var! {
    /// Copy mode of the logged packets.
    LogCopyMode, u8,
    None => 0,
    Meta => 1,
    Packet => 2
}

impl_var_trait! {
    /// Attributes inside a netfilter queue packet message.
    ///
    /// These are send by the kernel and describe a packet to be decided on. The same format of
    /// message is also sent as part of a verdict to the kernel.
    NfQueueAttr, u16, NlAttrType,
    PacketHdr => libc::NFQA_PACKET_HDR as u16,
    VerdictHdr => libc::NFQA_VERDICT_HDR as u16,
    Mark => libc::NFQA_MARK as u16,
    Timestamp => libc::NFQA_TIMESTAMP as u16,
    IfindexIndev => libc::NFQA_IFINDEX_INDEV as u16,
    IfindexOutdev => libc::NFQA_IFINDEX_OUTDEV as u16,
    IfindexPhyindev => libc::NFQA_IFINDEX_PHYSINDEV as u16,
    IfindexPhyoutdev => libc::NFQA_IFINDEX_PHYSOUTDEV as u16,
    Hwaddr => libc::NFQA_HWADDR as u16,
    Payload => libc::NFQA_PAYLOAD as u16,
    Ct => libc::NFQA_CT as u16,
    CtInfo => libc::NFQA_CT_INFO as u16,
    CapLen => libc::NFQA_CAP_LEN as u16,
    SkbInfo => libc::NFQA_SKB_INFO as u16,
    Exp => libc::NFQA_EXP as u16,
    Uid => libc::NFQA_UID as u16,
    Gid => libc::NFQA_GID as u16,
    SeqCtx => libc::NFQA_SECCTX as u16,
    Vlan => libc::NFQA_VLAN as u16,
    L2Hdr => libc::NFQA_L2HDR as u16
}

impl_var_trait! {
    /// Configuration attributes for netfilter queue.
    ///
    /// See [QueueConfigReq][crate::netfilter::QueueConfigReq]
    NfQueueCfg, u16, NlAttrType,
    Cmd => libc::NFQA_CFG_CMD as u16,
    Params => libc::NFQA_CFG_PARAMS as u16,
    QueueMaxlen => libc::NFQA_CFG_QUEUE_MAXLEN as u16,
    Mask => libc::NFQA_CFG_MASK as u16,
    Flags => libc::NFQA_CFG_FLAGS as u16
}

impl_trait! {
    /// Parameters for the [NfQueueCfg::Cmd].
    QueueCfgCmd, u8
}

impl_var_trait! {
    /// Command value for the [NfQueueCfg::Cmd].
    QueueCmd, u8, QueueCfgCmd,
    Bind => libc::NFQNL_CFG_CMD_BIND as u8,
    Unbind => libc::NFQNL_CFG_CMD_UNBIND as u8,
    PfBind => libc::NFQNL_CFG_CMD_PF_BIND as u8,
    PfUnbind => libc::NFQNL_CFG_CMD_PF_UNBIND as u8
}

impl_var! {
    /// Copy mode of the packets to be verdicted.
    QueueCopyMode, u8,
    None => libc::NFQNL_COPY_NONE as u8,
    Meta => libc::NFQNL_COPY_META as u8,
    Packet => libc::NFQNL_COPY_PACKET as u8
}

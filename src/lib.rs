#![no_std]

//! # Packet Builder
//!
//! A no_std library for building network packets.
//!
//! ## TCP Example
//!
//! ```ignore
//! use packet_builder::transport::tcp::{TcpPacket, options::TcpOption};
//!
//! // Create a TCP SYN packet with MSS option
//! let payload = b"";
//! let mut packet = TcpPacket::new(12345, 80, payload);
//!
//! // Set SYN flag
//! packet.header.flags.syn = true;
//! packet.header.sequence_number = 0x12345678;
//! packet.header.window = 65535;
//!
//! // Add Maximum Segment Size option
//! packet.options.add(TcpOption::MaximumSegmentSize(1460));
//!
//! // Generate packet bytes with checksum
//! let src_ip = [192, 168, 1, 100];
//! let dst_ip = [192, 168, 1, 1];
//! let packet_bytes = packet.to_bytes_ipv4(src_ip, dst_ip);
//!
//! // packet_bytes now contains a complete TCP segment
//! assert_eq!(24, packet_bytes.len()); // 20-byte header + 4-byte MSS option
//! ```

extern crate alloc;

pub mod address;
pub mod datalink;
pub mod network;
pub mod transport;

use crate::address::mac_addr::MacAddr;
use datalink::ethernet::EthernetFrame;
use datalink::ethernet::header::EthernetHeader;

pub struct PacketBuilder;

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder {
    pub fn new() -> Self {
        PacketBuilder
    }

    pub fn ethernet<'a>(
        &self,
        destination: MacAddr,
        source: MacAddr,
        ethertype: [u8; 2],
        payload: &'a [u8],
    ) -> EthernetFrame<'a> {
        EthernetFrame {
            header: EthernetHeader {
                dst: destination,
                src: source,
                ethertype,
            },
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datalink::ethernet::EthernetFrame;
    use datalink::ethernet::header::EthernetHeader;

    #[test]
    fn test_packet_builder_ethernet() {
        let builder = PacketBuilder::new();
        let expect = EthernetFrame {
            header: EthernetHeader {
                dst: MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
                src: MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
                ethertype: [0x08, 0x00],
            },
            payload: &[0x45, 0x00],
        };
        let actual = builder.ethernet(
            MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
            MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            [0x08, 0x00],
            &[0x45, 0x00],
        );
        assert_eq!(expect, actual);
    }
}

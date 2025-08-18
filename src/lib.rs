#![no_std]

pub mod address;
pub mod datalink;

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

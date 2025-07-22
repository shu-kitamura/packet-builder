#![no_std]

pub mod datalink;

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
        destination: [u8; 6],
        source: [u8; 6],
        ethertype: [u8; 2],
        payload: &'a [u8],
    ) -> EthernetFrame<'a> {
        EthernetFrame {
            header: EthernetHeader {
                destination_mac_address: destination,
                source_mac_address: source,
                ethertype,
            },
            payload,
        }
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
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
                destination_mac_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                source_mac_address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                ethertype: [0x08, 0x00],
            },
            payload: &[0x45, 0x00],
        };
        let actual = builder.ethernet(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x08, 0x00],
            &[0x45, 0x00],
        );
        assert_eq!(expect, actual);
    }
}

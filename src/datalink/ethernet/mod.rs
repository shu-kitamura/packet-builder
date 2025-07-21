pub mod ethertype;
pub mod header;

use header::EthernetHeader;

impl<'a> EthernetFrame<'a> {
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        let header = EthernetHeader::from_bytes(&bytes[0..14]);
        let payload = &bytes[14..];
        EthernetFrame { header, payload }
    }
}

#[derive(Debug, PartialEq)]
pub struct EthernetFrame<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use header::EthernetHeader;

    #[test]
    fn test_ethernet_frame_from_bytes() {
        let bytes: &[u8] = &[
            // Ethernet Header
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
            // Payload
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x01, 0xac, 0x10, 0x0a, 0x02,
        ];

        let ethernet_frame = EthernetFrame::from_bytes(bytes);

        let expect_header = EthernetHeader {
            destination_mac_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            source_mac_address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ethertype: [0x08, 0x00],
        };
        let expect_payload: &[u8] = &[
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x01, 0xac, 0x10, 0x0a, 0x02,
        ];

        assert_eq!(ethernet_frame.header, expect_header);
        assert_eq!(ethernet_frame.payload, expect_payload);
    }
}

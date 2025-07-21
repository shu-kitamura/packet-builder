#[derive(Debug, PartialEq)]
pub struct EthernetHeader {
    pub destination_mac_address: [u8; 6],
    pub source_mac_address: [u8; 6],
    pub ethertype: [u8; 2],
}

impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        EthernetHeader {
            destination_mac_address: bytes[0..6].try_into().expect("slice with incorrect length"),
            source_mac_address: bytes[6..12]
                .try_into()
                .expect("slice with incorrect length"),
            ethertype: bytes[12..14]
                .try_into()
                .expect("slice with incorrect length"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_header_from_bytes() {
        let bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
        ];
        let actual = EthernetHeader::from_bytes(bytes);
        let expect = EthernetHeader {
            destination_mac_address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            source_mac_address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ethertype: [0x08, 0x00],
        };
        assert_eq!(actual, expect);
    }
}

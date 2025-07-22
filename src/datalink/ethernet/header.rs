use crate::address::mac_address::MacAddress;

#[derive(Debug, PartialEq)]
pub struct EthernetHeader {
    pub destination_mac_address: MacAddress,
    pub source_mac_address: MacAddress,
    pub ethertype: [u8; 2],
}

impl EthernetHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        EthernetHeader {
            destination_mac_address: MacAddress::new(
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ),
            source_mac_address: MacAddress::new(
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ),
            ethertype: bytes[12..14]
                .try_into()
                .expect("slice with incorrect length"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::mac_address::MacAddress;

    #[test]
    fn test_ethernet_header_from_bytes() {
        let bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
        ];
        let actual = EthernetHeader::from_bytes(bytes);
        let expect = EthernetHeader {
            destination_mac_address: MacAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
            source_mac_address: MacAddress(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            ethertype: [0x08, 0x00],
        };
        assert_eq!(actual, expect);
    }
}

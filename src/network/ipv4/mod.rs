use alloc::vec::Vec;

pub mod header;
pub mod options;

use header::Ipv4Header;
use options::Ipv4Options;

/// IPv4 packet combining header, options, and payload
#[derive(Debug, PartialEq)]
pub struct Ipv4Packet<'a> {
    pub header: Ipv4Header,
    pub options: Ipv4Options,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, payload: &'a [u8]) -> Self {
        Ipv4Packet {
            header: Ipv4Header::new(src_ip, dst_ip, protocol),
            options: Ipv4Options::new(),
            payload,
        }
    }

    /// Calculate and set the correct IHL (Internet Header Length) based on header and options
    pub fn update_ihl(&mut self) {
        let header_words = 5; // Minimum header is 20 bytes = 5 words
        let option_words = self.options.words_needed();
        self.header.ihl = header_words + option_words;
    }

    /// Calculate and set the total length field
    pub fn update_total_length(&mut self) {
        let header_len = (self.header.ihl as u16) * 4;
        let total_len = header_len + self.payload.len() as u16;
        self.header.total_length = total_len;
    }

    /// Calculate IPv4 header checksum (header only, not payload)
    pub fn calculate_header_checksum(&self) -> u16 {
        let mut sum = 0u32;

        // Serialize header with checksum field set to 0
        let mut header_bytes = self.header.to_bytes();
        header_bytes[10] = 0; // Clear checksum field
        header_bytes[11] = 0;

        // Add options
        let option_bytes = self.options.to_bytes();
        header_bytes.extend_from_slice(&option_bytes);

        // Process header + options in 16-bit chunks
        for chunk in header_bytes.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8; // Pad with zero
            }
        }

        // Fold carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }

    /// Update IHL, total length, and checksum, then serialize the complete packet
    pub fn to_bytes(&mut self) -> Vec<u8> {
        // Update calculated fields
        self.update_ihl();
        self.update_total_length();

        // Calculate and set checksum
        self.header.header_checksum = self.calculate_header_checksum();

        // Serialize
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.options.to_bytes());
        bytes.extend_from_slice(self.payload);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use options::Ipv4Option;

    #[test]
    fn test_ipv4_packet_new() {
        let payload = b"Hello";
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 100];
        let protocol = 6; // TCP
        let actual = Ipv4Packet::new(src_ip, dst_ip, protocol, payload);

        assert_eq!(src_ip, actual.header.source_address);
        assert_eq!(dst_ip, actual.header.destination_address);
        assert_eq!(protocol, actual.header.protocol);
        assert_eq!(0, actual.options.options.len());
        assert_eq!(payload, actual.payload);
    }

    #[test]
    fn test_ipv4_packet_update_ihl() {
        let payload = b"Hello";
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 100];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 6, payload);

        // No options
        packet.update_ihl();
        assert_eq!(5, packet.header.ihl); // 20 bytes = 5 words

        // Add 4-byte option (End of Options List + padding)
        packet.options.add(Ipv4Option::EndOfOptionsList);
        packet.update_ihl();
        assert_eq!(6, packet.header.ihl); // 24 bytes = 6 words
    }

    #[test]
    fn test_ipv4_packet_basic() {
        // Test basic IPv4 packet without options
        let payload = b"Test";
        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 17, payload); // UDP protocol

        let actual = packet.to_bytes();

        // Verify structure
        assert_eq!(24, actual.len()); // 20-byte header + 4-byte payload

        // Verify header fields
        assert_eq!(0x45, actual[0]); // Version (4) + IHL (5)
        assert_eq!(0x00, actual[1]); // Type of Service
        assert_eq!(0x00, actual[2]); // Total length high byte (24 = 0x0018)
        assert_eq!(0x18, actual[3]); // Total length low byte

        // Verify protocol
        assert_eq!(17, actual[9]); // UDP protocol

        // Verify addresses
        assert_eq!(10, actual[12]); // Source IP first octet
        assert_eq!(0, actual[13]);
        assert_eq!(0, actual[14]);
        assert_eq!(1, actual[15]); // Source IP last octet

        assert_eq!(10, actual[16]); // Dest IP first octet
        assert_eq!(0, actual[17]);
        assert_eq!(0, actual[18]);
        assert_eq!(2, actual[19]); // Dest IP last octet

        // Verify payload
        assert_eq!(b"Test", &actual[20..24]);
    }

    #[test]
    fn test_ipv4_packet_with_options() {
        // Test IPv4 packet with options (EOL + padding)
        let payload = b"Data";
        let src_ip = [172, 16, 0, 1];
        let dst_ip = [172, 16, 0, 2];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 1, payload); // ICMP protocol

        // Add options
        packet.options.add(Ipv4Option::NoOperation);
        packet.options.add(Ipv4Option::EndOfOptionsList);

        let actual = packet.to_bytes();

        // Verify structure: 20-byte header + 4-byte options + 4-byte payload = 28 bytes
        assert_eq!(28, actual.len());

        // Verify header fields
        assert_eq!(0x46, actual[0]); // Version (4) + IHL (6) - 24 bytes header with options
        assert_eq!(0x00, actual[1]); // Type of Service
        assert_eq!(0x00, actual[2]); // Total length high byte (28 = 0x001C)
        assert_eq!(0x1C, actual[3]); // Total length low byte

        // Verify protocol
        assert_eq!(1, actual[9]); // ICMP protocol

        // Verify addresses
        assert_eq!(src_ip, &actual[12..16]);
        assert_eq!(dst_ip, &actual[16..20]);

        // Verify options
        assert_eq!(1, actual[20]); // NOP option
        assert_eq!(0, actual[21]); // EOL option
        assert_eq!(0, actual[22]); // Padding
        assert_eq!(0, actual[23]); // Padding

        // Verify payload
        assert_eq!(b"Data", &actual[24..28]);
    }

    #[test]
    fn test_ipv4_packet_fragmentation_flags() {
        // Test IPv4 packet with fragmentation flags
        let payload = b"Fragment";
        let src_ip = [203, 0, 113, 1];
        let dst_ip = [203, 0, 113, 2];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 17, payload); // UDP

        // Set fragmentation flags - this is a fragment with more fragments
        packet.header.flags.more_fragments = true;
        packet.header.fragment_offset = 185; // 185 * 8 = 1480 bytes offset
        packet.header.identification = 0xABCD;

        let actual = packet.to_bytes();

        // Verify structure
        assert_eq!(28, actual.len()); // 20-byte header + 8-byte payload

        // Verify fragment fields
        assert_eq!(0xAB, actual[4]); // ID high
        assert_eq!(0xCD, actual[5]); // ID low
        assert_eq!(0x20, actual[6]); // Flags (MF set) + fragment offset high (185 = 0x00B9)
        assert_eq!(0xB9, actual[7]); // Fragment offset low

        // Verify payload
        assert_eq!(b"Fragment", &actual[20..28]);
    }

    #[test]
    fn test_ipv4_packet_dont_fragment() {
        // Test IPv4 packet with Don't Fragment flag
        let payload = b"";
        let src_ip = [192, 0, 2, 1];
        let dst_ip = [192, 0, 2, 2];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 6, payload); // TCP

        packet.header.flags.dont_fragment = true;
        packet.header.identification = 0x1234;
        packet.header.type_of_service = 0x04; // Reliability bit set

        let actual = packet.to_bytes();

        // Verify structure
        assert_eq!(20, actual.len()); // 20-byte header only

        // Verify flags
        assert_eq!(0x40, actual[6]); // DF flag set, no fragment offset
        assert_eq!(0x00, actual[7]);

        // Verify ToS
        assert_eq!(0x04, actual[1]); // Reliability bit

        // Verify other fields
        assert_eq!(0x12, actual[4]); // ID high
        assert_eq!(0x34, actual[5]); // ID low
    }

    #[test]
    fn test_ipv4_header_checksum_calculation() {
        // Test header checksum calculation with known values
        let payload = b"Test payload";
        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        let mut packet = Ipv4Packet::new(src_ip, dst_ip, 17, payload);

        packet.header.identification = 0x1234;
        packet.header.time_to_live = 64;

        // Generate the packet bytes which will calculate and set the checksum
        let bytes = packet.to_bytes();
        let calculated_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);

        // Checksum should be non-zero and correctly calculated
        assert_ne!(0, calculated_checksum);

        // Verify that the stored checksum matches what was calculated
        assert_eq!(packet.header.header_checksum, calculated_checksum);
    }
}

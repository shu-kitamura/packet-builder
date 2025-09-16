use alloc::vec::Vec;

pub mod header;
pub mod options;

use header::TcpHeader;
use options::TcpOptions;

/// TCP packet combining header, options, and payload
#[derive(Debug, PartialEq)]
pub struct TcpPacket<'a> {
    pub header: TcpHeader,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn new(source_port: u16, destination_port: u16, payload: &'a [u8]) -> Self {
        TcpPacket {
            header: TcpHeader::new(source_port, destination_port),
            options: TcpOptions::new(),
            payload,
        }
    }

    /// Calculate and set the correct data_offset based on header and options
    pub fn update_data_offset(&mut self) {
        let header_words = 5; // Minimum header is 20 bytes = 5 words
        let option_words = self.options.words_needed();
        self.header.data_offset = header_words + option_words;
    }

    /// Calculate TCP checksum including pseudo-header
    pub fn calculate_checksum_ipv4(&self, src_ip: [u8; 4], dst_ip: [u8; 4]) -> u16 {
        let mut sum = 0u32;

        // IPv4 pseudo-header
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        sum += 6u32; // Protocol number for TCP

        let tcp_length = (self.header.data_offset as u32 * 4) + self.payload.len() as u32;
        sum += tcp_length;

        // TCP header (with checksum field set to 0)
        let mut header_bytes = self.header.to_bytes();
        header_bytes[16] = 0; // Clear checksum field
        header_bytes[17] = 0;

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

        // Add payload
        for chunk in self.payload.chunks(2) {
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

    /// Calculate TCP checksum including IPv6 pseudo-header
    pub fn calculate_checksum_ipv6(&self, src_ip: [u8; 16], dst_ip: [u8; 16]) -> u16 {
        let mut sum = 0u32;

        // IPv6 pseudo-header
        for chunk in src_ip.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        for chunk in dst_ip.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        let tcp_length = (self.header.data_offset as u32 * 4) + self.payload.len() as u32;
        sum += tcp_length;
        sum += 6u32; // Next header (TCP)

        // TCP header (with checksum field set to 0)
        let mut header_bytes = self.header.to_bytes();
        header_bytes[16] = 0; // Clear checksum field
        header_bytes[17] = 0;

        // Add options
        let option_bytes = self.options.to_bytes();
        header_bytes.extend_from_slice(&option_bytes);

        // Process header + options in 16-bit chunks
        for chunk in header_bytes.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        // Add payload
        for chunk in self.payload.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += (chunk[0] as u32) << 8;
            }
        }

        // Fold carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }

    /// Update checksum and data_offset, then serialize the complete packet
    pub fn to_bytes_ipv4(&mut self, src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        // Update data offset
        self.update_data_offset();

        // Calculate and set checksum
        self.header.checksum = self.calculate_checksum_ipv4(src_ip, dst_ip);

        // Serialize
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.options.to_bytes());
        bytes.extend_from_slice(self.payload);

        bytes
    }

    /// Update checksum and data_offset, then serialize the complete packet
    pub fn to_bytes_ipv6(&mut self, src_ip: [u8; 16], dst_ip: [u8; 16]) -> Vec<u8> {
        // Update data offset
        self.update_data_offset();

        // Calculate and set checksum
        self.header.checksum = self.calculate_checksum_ipv6(src_ip, dst_ip);

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
    use options::TcpOption;

    #[test]
    fn test_tcp_packet_new() {
        let payload = b"Hello";
        let actual = TcpPacket::new(80, 8080, payload);

        assert_eq!(80, actual.header.source_port);
        assert_eq!(8080, actual.header.destination_port);
        assert_eq!(0, actual.options.options.len());
        assert_eq!(payload, actual.payload);
    }

    #[test]
    fn test_tcp_packet_update_data_offset() {
        let payload = b"Hello";
        let mut packet = TcpPacket::new(80, 8080, payload);

        // No options
        packet.update_data_offset();
        assert_eq!(5, packet.header.data_offset); // 20 bytes = 5 words

        // Add MSS option (4 bytes = 1 word)
        packet.options.add(TcpOption::MaximumSegmentSize(1460));
        packet.update_data_offset();
        assert_eq!(6, packet.header.data_offset); // 24 bytes = 6 words
    }

    #[test]
    fn test_tcp_packet_syn_with_mss() {
        // Test a common scenario: SYN packet with MSS option
        let payload = b"";
        let mut packet = TcpPacket::new(12345, 80, payload);

        // Set SYN flag
        packet.header.flags.syn = true;
        packet.header.sequence_number = 0x12345678;
        packet.header.window = 65535;

        // Add MSS option
        packet.options.add(TcpOption::MaximumSegmentSize(1460));

        // Generate packet for IPv4
        let src_ip = [192, 168, 1, 100];
        let dst_ip = [192, 168, 1, 1];
        let actual = packet.to_bytes_ipv4(src_ip, dst_ip);

        // Verify structure
        assert_eq!(24, actual.len()); // 20-byte header + 4-byte option

        // Verify header fields
        assert_eq!(0x30, actual[0]); // Source port high byte (12345 = 0x3039)
        assert_eq!(0x39, actual[1]); // Source port low byte
        assert_eq!(0x00, actual[2]); // Dest port high byte (80 = 0x0050)
        assert_eq!(0x50, actual[3]); // Dest port low byte

        // Verify SYN flag
        assert_eq!(0x02, actual[13]); // SYN flag

        // Verify data offset
        assert_eq!(0x60, actual[12]); // Data offset = 6 (24 bytes)

        // Verify MSS option
        assert_eq!(0x02, actual[20]); // MSS option kind
        assert_eq!(0x04, actual[21]); // MSS option length
        assert_eq!(0x05, actual[22]); // MSS value high byte (1460 = 0x05B4)
        assert_eq!(0xb4, actual[23]); // MSS value low byte
    }

    #[test]
    fn test_tcp_checksum_ipv4() {
        // Test checksum calculation with known values
        let payload = b"";
        let mut packet = TcpPacket::new(80, 8080, payload);
        packet.header.sequence_number = 0x12345678;
        packet.header.flags.syn = true;

        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 100];

        let actual = packet.calculate_checksum_ipv4(src_ip, dst_ip);
        // Checksum should be non-zero
        assert_ne!(0, actual);
    }

    #[test]
    fn test_tcp_checksum_ipv6() {
        // Test checksum calculation with IPv6
        let payload = b"";
        let mut packet = TcpPacket::new(80, 8080, payload);
        packet.header.sequence_number = 0x12345678;
        packet.header.flags.syn = true;

        let src_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let dst_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let actual = packet.calculate_checksum_ipv6(src_ip, dst_ip);
        // Checksum should be non-zero
        assert_ne!(0, actual);
    }
}

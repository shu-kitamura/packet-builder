use alloc::vec::Vec;

#[derive(Debug, PartialEq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8, // 4 bits - number of 32-bit words in header
    pub reserved: u8,    // 3 bits - must be zero
    pub flags: TcpFlags, // 9 bits - control flags
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, PartialEq)]
pub struct TcpFlags {
    pub cwr: bool, // Congestion Window Reduced
    pub ece: bool, // ECN-Echo
    pub urg: bool, // Urgent pointer field is significant
    pub ack: bool, // Acknowledgment field is significant
    pub psh: bool, // Push function
    pub rst: bool, // Reset the connection
    pub syn: bool, // Synchronize sequence numbers
    pub fin: bool, // No more data from sender
}

impl TcpFlags {
    pub fn new() -> Self {
        TcpFlags {
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        }
    }

    /// Convert flags to a u16 value for serialization
    /// Bits: [Reserved(3)] [CWR][ECE][URG][ACK][PSH][RST][SYN][FIN]
    pub fn to_u16(&self) -> u16 {
        let mut flags = 0u16;
        if self.fin {
            flags |= 0x01;
        }
        if self.syn {
            flags |= 0x02;
        }
        if self.rst {
            flags |= 0x04;
        }
        if self.psh {
            flags |= 0x08;
        }
        if self.ack {
            flags |= 0x10;
        }
        if self.urg {
            flags |= 0x20;
        }
        if self.ece {
            flags |= 0x40;
        }
        if self.cwr {
            flags |= 0x80;
        }
        flags
    }

    /// Create flags from u16 value for deserialization
    pub fn from_u16(value: u16) -> Self {
        TcpFlags {
            fin: (value & 0x01) != 0,
            syn: (value & 0x02) != 0,
            rst: (value & 0x04) != 0,
            psh: (value & 0x08) != 0,
            ack: (value & 0x10) != 0,
            urg: (value & 0x20) != 0,
            ece: (value & 0x40) != 0,
            cwr: (value & 0x80) != 0,
        }
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpHeader {
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        TcpHeader {
            source_port,
            destination_port,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 5, // Minimum header size is 20 bytes (5 * 32-bit words)
            reserved: 0,
            flags: TcpFlags::new(),
            window: 0,
            checksum: 0,
            urgent_pointer: 0,
        }
    }

    /// Serialize TCP header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);

        // Source port (16 bits)
        bytes.extend_from_slice(&self.source_port.to_be_bytes());

        // Destination port (16 bits)
        bytes.extend_from_slice(&self.destination_port.to_be_bytes());

        // Sequence number (32 bits)
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());

        // Acknowledgment number (32 bits)
        bytes.extend_from_slice(&self.acknowledgment_number.to_be_bytes());

        // Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits)
        let data_offset_and_reserved = (self.data_offset << 4) | (self.reserved & 0x07);
        bytes.push(data_offset_and_reserved);
        bytes.push(self.flags.to_u16() as u8);

        // Window (16 bits)
        bytes.extend_from_slice(&self.window.to_be_bytes());

        // Checksum (16 bits)
        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        // Urgent pointer (16 bits)
        bytes.extend_from_slice(&self.urgent_pointer.to_be_bytes());

        bytes
    }

    /// Parse TCP header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 20 {
            panic!("TCP header must be at least 20 bytes");
        }

        let source_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let destination_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let sequence_number = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let acknowledgment_number = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let data_offset = (bytes[12] & 0xF0) >> 4;
        let reserved = (bytes[12] & 0x0E) >> 1;
        let flags = TcpFlags::from_u16(bytes[13] as u16);

        let window = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_pointer = u16::from_be_bytes([bytes[18], bytes[19]]);

        TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_pointer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_new() {
        let flags = TcpFlags::new();
        assert!(!flags.cwr);
        assert!(!flags.ece);
        assert!(!flags.urg);
        assert!(!flags.ack);
        assert!(!flags.psh);
        assert!(!flags.rst);
        assert!(!flags.syn);
        assert!(!flags.fin);
    }

    #[test]
    fn test_tcp_flags_to_u16() {
        let mut flags = TcpFlags::new();
        flags.syn = true;
        flags.ack = true;

        let expect = 0x12; // SYN (0x02) + ACK (0x10)
        let actual = flags.to_u16();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_flags_from_u16() {
        let flags_value = 0x12; // SYN + ACK
        let actual = TcpFlags::from_u16(flags_value);

        assert!(!actual.cwr);
        assert!(!actual.ece);
        assert!(!actual.urg);
        assert!(actual.ack);
        assert!(!actual.psh);
        assert!(!actual.rst);
        assert!(actual.syn);
        assert!(!actual.fin);
    }

    #[test]
    fn test_tcp_header_new() {
        let actual = TcpHeader::new(80, 8080);

        assert_eq!(80, actual.source_port);
        assert_eq!(8080, actual.destination_port);
        assert_eq!(0, actual.sequence_number);
        assert_eq!(0, actual.acknowledgment_number);
        assert_eq!(5, actual.data_offset);
        assert_eq!(0, actual.reserved);
        assert_eq!(TcpFlags::new(), actual.flags);
        assert_eq!(0, actual.window);
        assert_eq!(0, actual.checksum);
        assert_eq!(0, actual.urgent_pointer);
    }

    #[test]
    fn test_tcp_header_to_bytes() {
        let mut header = TcpHeader::new(80, 8080);
        header.sequence_number = 0x12345678;
        header.acknowledgment_number = 0x87654321;
        header.flags.syn = true;
        header.window = 65535;

        let actual = header.to_bytes();
        let expect = alloc::vec![
            0x00, 0x50, // Source port: 80
            0x1f, 0x90, // Destination port: 8080
            0x12, 0x34, 0x56, 0x78, // Sequence number
            0x87, 0x65, 0x43, 0x21, // Acknowledgment number
            0x50, // Data offset (5) + Reserved (0)
            0x02, // Flags: SYN
            0xff, 0xff, // Window: 65535
            0x00, 0x00, // Checksum: 0
            0x00, 0x00, // Urgent pointer: 0
        ];
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_header_from_bytes() {
        let bytes = alloc::vec![
            0x00, 0x50, // Source port: 80
            0x1f, 0x90, // Destination port: 8080
            0x12, 0x34, 0x56, 0x78, // Sequence number
            0x87, 0x65, 0x43, 0x21, // Acknowledgment number
            0x50, // Data offset (5) + Reserved (0)
            0x02, // Flags: SYN
            0xff, 0xff, // Window: 65535
            0x12, 0x34, // Checksum
            0x00, 0x00, // Urgent pointer: 0
        ];

        let actual = TcpHeader::from_bytes(&bytes);

        assert_eq!(80, actual.source_port);
        assert_eq!(8080, actual.destination_port);
        assert_eq!(0x12345678, actual.sequence_number);
        assert_eq!(0x87654321, actual.acknowledgment_number);
        assert_eq!(5, actual.data_offset);
        assert_eq!(0, actual.reserved);
        assert!(actual.flags.syn);
        assert!(!actual.flags.ack);
        assert_eq!(65535, actual.window);
        assert_eq!(0x1234, actual.checksum);
        assert_eq!(0, actual.urgent_pointer);
    }
}

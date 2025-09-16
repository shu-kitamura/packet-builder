use alloc::vec::Vec;

/// IPv4 header structure based on RFC 791
///
/// Reference: RFC 791 Section 3.1 - Internet Header Format
#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub version: u8,                  // 4 bits - IP version (always 4 for IPv4)
    pub ihl: u8,                      // 4 bits - Internet Header Length in 32-bit words
    pub type_of_service: u8,          // 8 bits - Type of Service (ToS) / DSCP
    pub total_length: u16,            // 16 bits - Total length of IP datagram in bytes
    pub identification: u16,          // 16 bits - Identification for fragmentation
    pub flags: Ipv4Flags,             // 3 bits - Control flags (Reserved, DF, MF)
    pub fragment_offset: u16,         // 13 bits - Fragment offset in 8-byte units
    pub time_to_live: u8,             // 8 bits - TTL
    pub protocol: u8,                 // 8 bits - Next level protocol
    pub header_checksum: u16,         // 16 bits - Header checksum
    pub source_address: [u8; 4],      // 32 bits - Source IP address
    pub destination_address: [u8; 4], // 32 bits - Destination IP address
}

/// IPv4 flags structure representing the 3-bit flags field
///
/// Reference: RFC 791 Section 3.1
/// Bit 0: Reserved (must be zero)
/// Bit 1: DF (Don't Fragment) - 0 = May Fragment, 1 = Don't Fragment
/// Bit 2: MF (More Fragments) - 0 = Last Fragment, 1 = More Fragments
#[derive(Debug, PartialEq)]
pub struct Ipv4Flags {
    pub reserved: bool,       // Bit 0 - Reserved, must be zero
    pub dont_fragment: bool,  // Bit 1 - DF flag
    pub more_fragments: bool, // Bit 2 - MF flag
}

impl Ipv4Flags {
    pub fn new() -> Self {
        Ipv4Flags {
            reserved: false,
            dont_fragment: false,
            more_fragments: false,
        }
    }

    /// Convert flags to a u16 value for serialization (3 bits in the upper part)
    /// The flags occupy the top 3 bits of a 16-bit field where the lower 13 bits
    /// are the fragment offset
    pub fn to_u16(&self, fragment_offset: u16) -> u16 {
        let mut flags = 0u16;
        if self.reserved {
            flags |= 0x8000; // Bit 15
        }
        if self.dont_fragment {
            flags |= 0x4000; // Bit 14
        }
        if self.more_fragments {
            flags |= 0x2000; // Bit 13
        }
        flags | (fragment_offset & 0x1FFF) // Lower 13 bits for fragment offset
    }

    /// Create flags from a u16 value during deserialization
    pub fn from_u16(value: u16) -> (Self, u16) {
        let flags = Ipv4Flags {
            reserved: (value & 0x8000) != 0,
            dont_fragment: (value & 0x4000) != 0,
            more_fragments: (value & 0x2000) != 0,
        };
        let fragment_offset = value & 0x1FFF;
        (flags, fragment_offset)
    }
}

impl Default for Ipv4Flags {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipv4Header {
    pub fn new(source_address: [u8; 4], destination_address: [u8; 4], protocol: u8) -> Self {
        Ipv4Header {
            version: 4,
            ihl: 5, // Minimum header length (20 bytes = 5 words)
            type_of_service: 0,
            total_length: 0, // Will be calculated later
            identification: 0,
            flags: Ipv4Flags::new(),
            fragment_offset: 0,
            time_to_live: 64, // Default TTL
            protocol,
            header_checksum: 0, // Will be calculated later
            source_address,
            destination_address,
        }
    }

    /// Serialize IPv4 header to bytes (network byte order)
    ///
    /// Reference: RFC 791 Section 3.1 for field layout
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);

        // Byte 0: Version (4 bits) + IHL (4 bits)
        bytes.push((self.version << 4) | (self.ihl & 0x0F));

        // Byte 1: Type of Service
        bytes.push(self.type_of_service);

        // Bytes 2-3: Total Length (big-endian)
        bytes.extend_from_slice(&self.total_length.to_be_bytes());

        // Bytes 4-5: Identification (big-endian)
        bytes.extend_from_slice(&self.identification.to_be_bytes());

        // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits) (big-endian)
        let flags_and_frag = self.flags.to_u16(self.fragment_offset);
        bytes.extend_from_slice(&flags_and_frag.to_be_bytes());

        // Byte 8: Time to Live
        bytes.push(self.time_to_live);

        // Byte 9: Protocol
        bytes.push(self.protocol);

        // Bytes 10-11: Header Checksum (big-endian)
        bytes.extend_from_slice(&self.header_checksum.to_be_bytes());

        // Bytes 12-15: Source Address
        bytes.extend_from_slice(&self.source_address);

        // Bytes 16-19: Destination Address
        bytes.extend_from_slice(&self.destination_address);

        bytes
    }

    /// Deserialize IPv4 header from bytes (network byte order)
    ///
    /// Reference: RFC 791 Section 3.1 for field layout
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 {
            return Err("IPv4 header must be at least 20 bytes");
        }

        // Byte 0: Version + IHL
        let version_ihl = bytes[0];
        let version = (version_ihl >> 4) & 0x0F;
        let ihl = version_ihl & 0x0F;

        if version != 4 {
            return Err("Invalid IP version");
        }

        if ihl < 5 {
            return Err("Invalid IHL (must be at least 5)");
        }

        // Byte 1: Type of Service
        let type_of_service = bytes[1];

        // Bytes 2-3: Total Length
        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);

        // Bytes 4-5: Identification
        let identification = u16::from_be_bytes([bytes[4], bytes[5]]);

        // Bytes 6-7: Flags + Fragment Offset
        let flags_and_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let (flags, fragment_offset) = Ipv4Flags::from_u16(flags_and_frag);

        // Byte 8: Time to Live
        let time_to_live = bytes[8];

        // Byte 9: Protocol
        let protocol = bytes[9];

        // Bytes 10-11: Header Checksum
        let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);

        // Bytes 12-15: Source Address
        let source_address = [bytes[12], bytes[13], bytes[14], bytes[15]];

        // Bytes 16-19: Destination Address
        let destination_address = [bytes[16], bytes[17], bytes[18], bytes[19]];

        Ok(Ipv4Header {
            version,
            ihl,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            time_to_live,
            protocol,
            header_checksum,
            source_address,
            destination_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_flags_new() {
        let flags = Ipv4Flags::new();
        assert!(!flags.reserved);
        assert!(!flags.dont_fragment);
        assert!(!flags.more_fragments);
    }

    #[test]
    fn test_ipv4_flags_to_u16() {
        let mut flags = Ipv4Flags::new();

        // Test no flags set with fragment offset
        assert_eq!(0x0100, flags.to_u16(0x0100)); // Fragment offset only

        // Test DF flag
        flags.dont_fragment = true;
        assert_eq!(0x4100, flags.to_u16(0x0100)); // DF + fragment offset

        // Test MF flag
        flags.dont_fragment = false;
        flags.more_fragments = true;
        assert_eq!(0x2100, flags.to_u16(0x0100)); // MF + fragment offset

        // Test both flags
        flags.dont_fragment = true;
        flags.more_fragments = true;
        assert_eq!(0x6100, flags.to_u16(0x0100)); // DF + MF + fragment offset
    }

    #[test]
    fn test_ipv4_flags_from_u16() {
        // Test no flags
        let (flags, frag_offset) = Ipv4Flags::from_u16(0x0100);
        assert!(!flags.reserved);
        assert!(!flags.dont_fragment);
        assert!(!flags.more_fragments);
        assert_eq!(0x0100, frag_offset);

        // Test DF flag
        let (flags, frag_offset) = Ipv4Flags::from_u16(0x4100);
        assert!(!flags.reserved);
        assert!(flags.dont_fragment);
        assert!(!flags.more_fragments);
        assert_eq!(0x0100, frag_offset);

        // Test MF flag
        let (flags, frag_offset) = Ipv4Flags::from_u16(0x2100);
        assert!(!flags.reserved);
        assert!(!flags.dont_fragment);
        assert!(flags.more_fragments);
        assert_eq!(0x0100, frag_offset);
    }

    #[test]
    fn test_ipv4_header_new() {
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [10, 0, 0, 1];
        let protocol = 6; // TCP
        let header = Ipv4Header::new(src_ip, dst_ip, protocol);

        assert_eq!(4, header.version);
        assert_eq!(5, header.ihl);
        assert_eq!(0, header.type_of_service);
        assert_eq!(src_ip, header.source_address);
        assert_eq!(dst_ip, header.destination_address);
        assert_eq!(protocol, header.protocol);
        assert_eq!(64, header.time_to_live);
    }

    #[test]
    fn test_ipv4_header_to_bytes() {
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [10, 0, 0, 1];
        let mut header = Ipv4Header::new(src_ip, dst_ip, 6);
        header.total_length = 40; // 20-byte header + 20-byte payload
        header.identification = 0x1234;
        header.flags.dont_fragment = true;
        header.header_checksum = 0x5678;

        let bytes = header.to_bytes();
        assert_eq!(20, bytes.len());

        // Check specific fields
        assert_eq!(0x45, bytes[0]); // Version (4) + IHL (5)
        assert_eq!(0x00, bytes[1]); // ToS
        assert_eq!(0x00, bytes[2]); // Total length high
        assert_eq!(0x28, bytes[3]); // Total length low (40)
        assert_eq!(0x12, bytes[4]); // ID high
        assert_eq!(0x34, bytes[5]); // ID low
        assert_eq!(0x40, bytes[6]); // Flags (DF set)
        assert_eq!(0x00, bytes[7]); // Fragment offset
        assert_eq!(64, bytes[8]); // TTL
        assert_eq!(6, bytes[9]); // Protocol
        assert_eq!(0x56, bytes[10]); // Checksum high
        assert_eq!(0x78, bytes[11]); // Checksum low

        // Check addresses
        assert_eq!(src_ip, &bytes[12..16]);
        assert_eq!(dst_ip, &bytes[16..20]);
    }

    #[test]
    fn test_ipv4_header_from_bytes() {
        let bytes = [
            0x45, 0x00, 0x00, 0x28, // Version, IHL, ToS, Total Length
            0x12, 0x34, 0x40, 0x00, // ID, Flags (DF), Fragment Offset
            0x40, 0x06, 0x56, 0x78, // TTL, Protocol, Checksum
            0xC0, 0xA8, 0x01, 0x01, // Source IP (192.168.1.1)
            0x0A, 0x00, 0x00, 0x01, // Dest IP (10.0.0.1)
        ];

        let header = Ipv4Header::from_bytes(&bytes).unwrap();

        assert_eq!(4, header.version);
        assert_eq!(5, header.ihl);
        assert_eq!(0, header.type_of_service);
        assert_eq!(40, header.total_length);
        assert_eq!(0x1234, header.identification);
        assert!(header.flags.dont_fragment);
        assert!(!header.flags.more_fragments);
        assert_eq!(0, header.fragment_offset);
        assert_eq!(64, header.time_to_live);
        assert_eq!(6, header.protocol);
        assert_eq!(0x5678, header.header_checksum);
        assert_eq!([192, 168, 1, 1], header.source_address);
        assert_eq!([10, 0, 0, 1], header.destination_address);
    }

    #[test]
    fn test_ipv4_header_from_bytes_invalid() {
        // Too short
        let short_bytes = [0x45, 0x00];
        assert!(Ipv4Header::from_bytes(&short_bytes).is_err());

        // Invalid version
        let invalid_version = [
            0x55, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x56, 0x78, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        assert!(Ipv4Header::from_bytes(&invalid_version).is_err());

        // Invalid IHL (less than 5)
        let invalid_ihl = [
            0x44, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x56, 0x78, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        assert!(Ipv4Header::from_bytes(&invalid_ihl).is_err());
    }
}

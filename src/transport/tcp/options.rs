use alloc::vec::Vec;

#[derive(Debug, PartialEq, Clone)]
pub enum TcpOption {
    /// End of Option List (Kind=0)
    EndOfOptionList,
    /// No Operation (Kind=1) - used for padding
    NoOperation,
    /// Maximum Segment Size (Kind=2, Length=4)
    MaximumSegmentSize(u16),
}

impl TcpOption {
    /// Get the kind field for this option
    pub fn kind(&self) -> u8 {
        match self {
            TcpOption::EndOfOptionList => 0,
            TcpOption::NoOperation => 1,
            TcpOption::MaximumSegmentSize(_) => 2,
        }
    }

    /// Get the length field for this option (including kind and length fields)
    pub fn length(&self) -> u8 {
        match self {
            TcpOption::EndOfOptionList => 1,
            TcpOption::NoOperation => 1,
            TcpOption::MaximumSegmentSize(_) => 4,
        }
    }

    /// Serialize this option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TcpOption::EndOfOptionList => alloc::vec![0],
            TcpOption::NoOperation => alloc::vec![1],
            TcpOption::MaximumSegmentSize(mss) => {
                let mut bytes = alloc::vec![2, 4]; // Kind=2, Length=4
                bytes.extend_from_slice(&mss.to_be_bytes());
                bytes
            }
        }
    }

    /// Parse a single option from bytes, returns (option, bytes_consumed)
    pub fn from_bytes(bytes: &[u8]) -> Result<(TcpOption, usize), &'static str> {
        if bytes.is_empty() {
            return Err("Empty bytes for TCP option");
        }

        match bytes[0] {
            0 => Ok((TcpOption::EndOfOptionList, 1)),
            1 => Ok((TcpOption::NoOperation, 1)),
            2 => {
                if bytes.len() < 4 {
                    return Err("MSS option requires 4 bytes");
                }
                if bytes[1] != 4 {
                    return Err("MSS option length must be 4");
                }
                let mss = u16::from_be_bytes([bytes[2], bytes[3]]);
                Ok((TcpOption::MaximumSegmentSize(mss), 4))
            }
            _ => Err("Unknown TCP option kind"),
        }
    }
}

/// Collection of TCP options with serialization support
#[derive(Debug, PartialEq)]
pub struct TcpOptions {
    pub options: Vec<TcpOption>,
}

impl TcpOptions {
    pub fn new() -> Self {
        TcpOptions {
            options: Vec::new(),
        }
    }

    /// Add an option to the collection
    pub fn add(&mut self, option: TcpOption) {
        self.options.push(option);
    }

    /// Calculate the total length of options in bytes
    pub fn total_length(&self) -> usize {
        self.options.iter().map(|opt| opt.length() as usize).sum()
    }

    /// Calculate how many 32-bit words are needed for options (including padding)
    #[allow(clippy::manual_div_ceil)]
    pub fn words_needed(&self) -> u8 {
        let byte_length = self.total_length();
        ((byte_length + 3) / 4) as u8 // Round up to nearest 32-bit word
    }

    /// Serialize options to bytes with proper padding
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add all options
        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        // Add padding to align to 32-bit word boundary
        let words_needed = self.words_needed() as usize;
        let target_length = words_needed * 4;

        while bytes.len() < target_length {
            bytes.push(0); // Pad with zeros
        }

        bytes
    }

    /// Parse options from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut options = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            // Skip padding zeros at the end
            if bytes[offset] == 0 {
                break;
            }

            let (option, consumed) = TcpOption::from_bytes(&bytes[offset..])?;
            options.push(option.clone());
            offset += consumed;

            // End of option list terminates parsing
            if let TcpOption::EndOfOptionList = option {
                break;
            }
        }

        Ok(TcpOptions { options })
    }
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_option_end_of_list() {
        let option = TcpOption::EndOfOptionList;
        assert_eq!(0, option.kind());
        assert_eq!(1, option.length());

        let expect = alloc::vec![0];
        let actual = option.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_option_no_operation() {
        let option = TcpOption::NoOperation;
        assert_eq!(1, option.kind());
        assert_eq!(1, option.length());

        let expect = alloc::vec![1];
        let actual = option.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_option_mss() {
        let option = TcpOption::MaximumSegmentSize(1460);
        assert_eq!(2, option.kind());
        assert_eq!(4, option.length());

        let expect = alloc::vec![2, 4, 0x05, 0xb4]; // Kind=2, Length=4, MSS=1460
        let actual = option.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_option_from_bytes_eol() {
        let bytes = alloc::vec![0];
        let (actual, consumed) = TcpOption::from_bytes(&bytes).unwrap();

        assert_eq!(TcpOption::EndOfOptionList, actual);
        assert_eq!(1, consumed);
    }

    #[test]
    fn test_tcp_option_from_bytes_nop() {
        let bytes = alloc::vec![1];
        let (actual, consumed) = TcpOption::from_bytes(&bytes).unwrap();

        assert_eq!(TcpOption::NoOperation, actual);
        assert_eq!(1, consumed);
    }

    #[test]
    fn test_tcp_option_from_bytes_mss() {
        let bytes = alloc::vec![2, 4, 0x05, 0xb4]; // MSS=1460
        let (actual, consumed) = TcpOption::from_bytes(&bytes).unwrap();

        assert_eq!(TcpOption::MaximumSegmentSize(1460), actual);
        assert_eq!(4, consumed);
    }

    #[test]
    fn test_tcp_options_new() {
        let options = TcpOptions::new();
        assert!(options.options.is_empty());
        assert_eq!(0, options.total_length());
        assert_eq!(0, options.words_needed());
    }

    #[test]
    fn test_tcp_options_add_mss() {
        let mut options = TcpOptions::new();
        options.add(TcpOption::MaximumSegmentSize(1460));

        assert_eq!(1, options.options.len());
        assert_eq!(4, options.total_length());
        assert_eq!(1, options.words_needed()); // 4 bytes = 1 word
    }

    #[test]
    fn test_tcp_options_padding() {
        let mut options = TcpOptions::new();
        options.add(TcpOption::NoOperation); // 1 byte
        options.add(TcpOption::MaximumSegmentSize(1460)); // 4 bytes
        // Total: 5 bytes, needs to be padded to 8 bytes (2 words)

        assert_eq!(5, options.total_length());
        assert_eq!(2, options.words_needed()); // 5 bytes -> 2 words (8 bytes)

        let actual = options.to_bytes();
        let expect = alloc::vec![
            1, // NOP
            2, 4, 0x05, 0xb4, // MSS=1460
            0, 0, 0 // Padding to 8 bytes
        ];
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_options_syn_with_mss() {
        // Common case: SYN packet with MSS option
        let mut options = TcpOptions::new();
        options.add(TcpOption::MaximumSegmentSize(1460));

        let actual = options.to_bytes();
        let expect = alloc::vec![2, 4, 0x05, 0xb4]; // Exactly 4 bytes, no padding needed
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_tcp_options_from_bytes() {
        let bytes = alloc::vec![
            1, // NOP
            2, 4, 0x05, 0xb4, // MSS=1460
            0, 0, 0 // Padding
        ];

        let actual = TcpOptions::from_bytes(&bytes).unwrap();

        assert_eq!(2, actual.options.len());
        assert_eq!(TcpOption::NoOperation, actual.options[0]);
        assert_eq!(TcpOption::MaximumSegmentSize(1460), actual.options[1]);
    }
}

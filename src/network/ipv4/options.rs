use alloc::vec;
use alloc::vec::Vec;

/// IPv4 option types as defined in RFC 791
///
/// Reference: RFC 791 Section 3.1 - Options
#[derive(Debug, PartialEq, Clone)]
pub enum Ipv4Option {
    /// End of Option List (Type 0)
    /// Single byte option indicating end of options
    EndOfOptionsList,

    /// No Operation (Type 1)
    /// Single byte option used for alignment
    NoOperation,
}

impl Ipv4Option {
    /// Get the option type code
    pub fn option_type(&self) -> u8 {
        match self {
            Ipv4Option::EndOfOptionsList => 0,
            Ipv4Option::NoOperation => 1,
        }
    }

    /// Get the length of this option in bytes
    pub fn length(&self) -> usize {
        match self {
            Ipv4Option::EndOfOptionsList => 1,
            Ipv4Option::NoOperation => 1,
        }
    }

    /// Serialize option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Ipv4Option::EndOfOptionsList => vec![0],
            Ipv4Option::NoOperation => vec![1],
        }
    }

    /// Deserialize option from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.is_empty() {
            return Err("Empty option bytes");
        }

        let option_type = bytes[0];
        match option_type {
            0 => Ok((Ipv4Option::EndOfOptionsList, 1)),
            1 => Ok((Ipv4Option::NoOperation, 1)),
            _ => Err("Unknown option type"),
        }
    }
}

/// Collection of IPv4 options
///
/// Handles proper padding to maintain 32-bit word alignment as required by RFC 791
#[derive(Debug, PartialEq)]
pub struct Ipv4Options {
    pub options: Vec<Ipv4Option>,
}

impl Ipv4Options {
    pub fn new() -> Self {
        Ipv4Options {
            options: Vec::new(),
        }
    }

    /// Add an option to the collection
    pub fn add(&mut self, option: Ipv4Option) {
        self.options.push(option);
    }

    /// Get the total length of all options in bytes (including padding)
    pub fn total_length(&self) -> usize {
        let mut length = 0;
        for option in &self.options {
            length += option.length();
        }

        // Pad to next 32-bit boundary
        let remainder = length % 4;
        if remainder != 0 {
            length += 4 - remainder;
        }

        length
    }

    /// Calculate number of 32-bit words needed for options (including padding)
    pub fn words_needed(&self) -> u8 {
        let total_bytes = self.total_length();
        (total_bytes / 4) as u8
    }

    /// Serialize options to bytes with proper padding
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize all options
        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        // Add padding to reach 32-bit boundary
        let remainder = bytes.len() % 4;
        if remainder != 0 {
            let padding_needed = 4 - remainder;
            bytes.resize(bytes.len() + padding_needed, 0);
        }

        bytes
    }

    /// Deserialize options from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut options = Vec::new();
        let mut pos = 0;

        while pos < bytes.len() {
            let (option, consumed) = Ipv4Option::from_bytes(&bytes[pos..])?;
            options.push(option.clone());
            pos += consumed;

            // If we encounter an End of Options List, stop processing
            if matches!(option, Ipv4Option::EndOfOptionsList) {
                break;
            }
        }

        Ok(Ipv4Options { options })
    }
}

impl Default for Ipv4Options {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_option_end_of_list() {
        let option = Ipv4Option::EndOfOptionsList;
        assert_eq!(0, option.option_type());
        assert_eq!(1, option.length());
        assert_eq!(vec![0], option.to_bytes());
    }

    #[test]
    fn test_ipv4_option_no_operation() {
        let option = Ipv4Option::NoOperation;
        assert_eq!(1, option.option_type());
        assert_eq!(1, option.length());
        assert_eq!(vec![1], option.to_bytes());
    }

    #[test]
    fn test_ipv4_option_from_bytes_eol() {
        let bytes = [0];
        let (option, consumed) = Ipv4Option::from_bytes(&bytes).unwrap();
        assert_eq!(Ipv4Option::EndOfOptionsList, option);
        assert_eq!(1, consumed);
    }

    #[test]
    fn test_ipv4_option_from_bytes_nop() {
        let bytes = [1];
        let (option, consumed) = Ipv4Option::from_bytes(&bytes).unwrap();
        assert_eq!(Ipv4Option::NoOperation, option);
        assert_eq!(1, consumed);
    }

    #[test]
    fn test_ipv4_option_from_bytes_unknown() {
        let bytes = [255];
        assert!(Ipv4Option::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_ipv4_options_new() {
        let options = Ipv4Options::new();
        assert_eq!(0, options.options.len());
        assert_eq!(0, options.total_length());
        assert_eq!(0, options.words_needed());
    }

    #[test]
    fn test_ipv4_options_add_single() {
        let mut options = Ipv4Options::new();
        options.add(Ipv4Option::EndOfOptionsList);

        assert_eq!(1, options.options.len());
        assert_eq!(4, options.total_length()); // 1 byte + 3 bytes padding
        assert_eq!(1, options.words_needed());
    }

    #[test]
    fn test_ipv4_options_add_multiple() {
        let mut options = Ipv4Options::new();
        options.add(Ipv4Option::NoOperation);
        options.add(Ipv4Option::NoOperation);
        options.add(Ipv4Option::EndOfOptionsList);

        assert_eq!(3, options.options.len());
        assert_eq!(4, options.total_length()); // 3 bytes + 1 byte padding
        assert_eq!(1, options.words_needed());
    }

    #[test]
    fn test_ipv4_options_padding() {
        let mut options = Ipv4Options::new();

        // Add options that require padding
        options.add(Ipv4Option::EndOfOptionsList);

        let bytes = options.to_bytes();
        assert_eq!(4, bytes.len()); // 1 option byte + 3 padding bytes
        assert_eq!(0, bytes[0]); // EOL option
        assert_eq!(0, bytes[1]); // Padding
        assert_eq!(0, bytes[2]); // Padding
        assert_eq!(0, bytes[3]); // Padding
    }

    #[test]
    fn test_ipv4_options_no_padding_needed() {
        let mut options = Ipv4Options::new();

        // Add exactly 4 bytes of options (no padding needed)
        options.add(Ipv4Option::NoOperation);
        options.add(Ipv4Option::NoOperation);
        options.add(Ipv4Option::NoOperation);
        options.add(Ipv4Option::EndOfOptionsList);

        let bytes = options.to_bytes();
        assert_eq!(4, bytes.len()); // Exactly 4 bytes, no padding
        assert_eq!(1, bytes[0]); // NOP
        assert_eq!(1, bytes[1]); // NOP
        assert_eq!(1, bytes[2]); // NOP
        assert_eq!(0, bytes[3]); // EOL
    }

    #[test]
    fn test_ipv4_options_from_bytes() {
        // Test parsing options with padding
        let bytes = [1, 1, 0, 0]; // NOP, NOP, EOL, padding
        let options = Ipv4Options::from_bytes(&bytes).unwrap();

        assert_eq!(3, options.options.len());
        assert_eq!(Ipv4Option::NoOperation, options.options[0]);
        assert_eq!(Ipv4Option::NoOperation, options.options[1]);
        assert_eq!(Ipv4Option::EndOfOptionsList, options.options[2]);
    }

    #[test]
    fn test_ipv4_options_from_bytes_only_padding() {
        // Test parsing only padding (no explicit options)
        let bytes = [0, 0, 0, 0];
        let options = Ipv4Options::from_bytes(&bytes).unwrap();

        assert_eq!(1, options.options.len());
        assert_eq!(Ipv4Option::EndOfOptionsList, options.options[0]);
    }
}

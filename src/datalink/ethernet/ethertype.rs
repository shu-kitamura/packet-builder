use core::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Unknown,
}

impl EtherType {
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if let Ok(ethertype) = EtherType::try_from(bytes) {
            ethertype
        } else {
            EtherType::Unknown
        }
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self) -> [u8; 2] {
        match self {
            EtherType::Ipv4 => [0x08, 0x00],
            EtherType::Ipv6 => [0x86, 0xDD],
            EtherType::Arp => [0x08, 0x06],
            EtherType::Unknown => [0x00, 0x00],
        }
    }
}

impl TryFrom<[u8; 2]> for EtherType {
    type Error = ();

    fn try_from(bytes: [u8; 2]) -> Result<Self, Self::Error> {
        match (bytes[0], bytes[1]) {
            (0x08, 0x00) => Ok(EtherType::Ipv4),
            (0x86, 0xDD) => Ok(EtherType::Ipv6),
            (0x08, 0x06) => Ok(EtherType::Arp),
            _ => Ok(EtherType::Unknown),
        }
    }
}

impl TryFrom<&[u8]> for EtherType {
    type Error = ();

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 2 {
            return Err(());
        }
        let bytes_arr: [u8; 2] = [bytes[0], bytes[1]];
        EtherType::try_from(bytes_arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes_ipv4() {
        let bytes = [0x08, 0x00];
        let expect = EtherType::Ipv4;
        let actual = EtherType::from_bytes(&bytes);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_from_bytes_ipv6() {
        let bytes = [0x86, 0xDD];
        let expect = EtherType::Ipv6;
        let actual = EtherType::from_bytes(&bytes);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_from_bytes_arp() {
        let bytes = [0x08, 0x06];
        let expect = EtherType::Arp;
        let actual = EtherType::from_bytes(&bytes);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_from_bytes_unknown() {
        let bytes = [0x00, 0x00];
        let expect = EtherType::Unknown;
        let actual = EtherType::from_bytes(&bytes);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_try_from_ipv4() {
        let bytes = [0x08, 0x00];
        let expect = EtherType::Ipv4;
        let actual = EtherType::try_from(bytes).unwrap();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_try_from_ipv6() {
        let bytes = [0x86, 0xDD];
        let expect = EtherType::Ipv6;
        let actual = EtherType::try_from(bytes).unwrap();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_try_from_arp() {
        let bytes = [0x08, 0x06];
        let expect = EtherType::Arp;
        let actual = EtherType::try_from(bytes).unwrap();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_try_from_unknown() {
        let bytes = [0x00, 0x00];
        let expect = EtherType::Unknown;
        let actual = EtherType::try_from(bytes).unwrap();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_try_from_invalid() {
        let bytes: &[u8] = &[0x00, 0x00, 0x00];
        let actual = EtherType::try_from(bytes);
        assert!(actual.is_err());
    }

    #[test]
    fn test_to_bytes_ipv4() {
        let ethertype = EtherType::Ipv4;
        let expect = [0x08, 0x00];
        let actual = ethertype.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_to_bytes_ipv6() {
        let ethertype = EtherType::Ipv6;
        let expect = [0x86, 0xDD];
        let actual = ethertype.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_to_bytes_arp() {
        let ethertype = EtherType::Arp;
        let expect = [0x08, 0x06];
        let actual = ethertype.to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_to_bytes_unknown() {
        let ethertype = EtherType::Unknown;
        let expect = [0x00, 0x00];
        let actual = ethertype.to_bytes();
        assert_eq!(expect, actual);
    }
}

use core::fmt;

const MULTICAST_BIT: u8 = 0x01;
const LOCAL_BIT: u8 = 0x02;

#[derive(Debug, PartialEq)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8, o5: u8, o6: u8) -> MacAddr {
        MacAddr(o1, o2, o3, o4, o5, o6)
    }

    pub fn broadcast() -> MacAddr {
        MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
    }

    pub fn octets(&self) -> [u8; 6] {
        [self.0, self.1, self.2, self.3, self.4, self.5]
    }

    pub fn is_broadcast(&self) -> bool {
        self == &Self::broadcast()
    }

    pub fn is_multicast(&self) -> bool {
        (self.0 & MULTICAST_BIT) == MULTICAST_BIT
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    pub fn is_local(&self) -> bool {
        (self.0 & LOCAL_BIT) == LOCAL_BIT
    }

    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_new() {
        let expect = MacAddr(1, 2, 3, 4, 5, 6);
        let actual = MacAddr::new(1, 2, 3, 4, 5, 6);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_broadcast() {
        let expect = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        let actual = MacAddr::broadcast();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_octets() {
        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let expect = [1, 2, 3, 4, 5, 6];
        let actual = mac.octets();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_is_broadcast() {
        let mac = MacAddr::broadcast();
        assert!(mac.is_broadcast());

        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        assert!(!mac.is_broadcast());
    }

    #[test]
    fn test_is_multicast() {
        let mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_multicast());

        let mac = MacAddr::new(0x00, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_multicast());
    }

    #[test]
    fn test_is_unicast() {
        let mac = MacAddr::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_unicast());

        let mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_unicast());
    }

    #[test]
    fn test_is_local() {
        let mac = MacAddr::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_local());

        let mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_local());
    }

    #[test]
    fn test_is_universal() {
        let mac = MacAddr::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_universal());

        let mac = MacAddr::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_universal());
    }

    #[test]
    fn test_display() {
        let mac = MacAddr::new(0x00, 0x01, 0x02, 0x03, 0x04, 0x05);
        let expect = "00:01:02:03:04:05";
        let actual = mac.to_string();
        assert_eq!(expect, actual);
    }
}

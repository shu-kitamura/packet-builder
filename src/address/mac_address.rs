const MULTICAST_BIT: u8 = 0x01;
const LOCAL_BIT: u8 = 0x02;

#[derive(Debug, PartialEq)]
pub struct MacAddress(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddress {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8, o5: u8, o6: u8) -> MacAddress {
        MacAddress(o1, o2, o3, o4, o5, o6)
    }

    pub fn broadcast() -> MacAddress {
        MacAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let expect = MacAddress(1, 2, 3, 4, 5, 6);
        let actual = MacAddress::new(1, 2, 3, 4, 5, 6);
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_broadcast() {
        let expect = MacAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        let actual = MacAddress::broadcast();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_octets() {
        let mac = MacAddress::new(1, 2, 3, 4, 5, 6);
        let expect = [1, 2, 3, 4, 5, 6];
        let actual = mac.octets();
        assert_eq!(expect, actual);
    }

    #[test]
    fn test_is_broadcast() {
        let mac = MacAddress::broadcast();
        assert!(mac.is_broadcast());

        let mac = MacAddress::new(1, 2, 3, 4, 5, 6);
        assert!(!mac.is_broadcast());
    }

    #[test]
    fn test_is_multicast() {
        let mac = MacAddress::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_multicast());

        let mac = MacAddress::new(0x00, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_multicast());
    }

    #[test]
    fn test_is_unicast() {
        let mac = MacAddress::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_unicast());

        let mac = MacAddress::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_unicast());
    }

    #[test]
    fn test_is_local() {
        let mac = MacAddress::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_local());

        let mac = MacAddress::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_local());
    }

    #[test]
    fn test_is_universal() {
        let mac = MacAddress::new(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(mac.is_universal());

        let mac = MacAddress::new(0x02, 0x02, 0x03, 0x04, 0x05, 0x06);
        assert!(!mac.is_universal());
    }
}

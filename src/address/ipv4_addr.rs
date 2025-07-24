#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Addr {
    pub octet1: u8,
    pub octet2: u8,
    pub octet3: u8,
    pub octet4: u8,
}

impl Ipv4Addr {
    pub fn new(octet1: u8, octet2: u8, octet3: u8, octet4: u8) -> Self {
        Self {
            octet1,
            octet2,
            octet3,
            octet4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let expect = Ipv4Addr::new(127, 0, 0, 1);
        let actual = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(expect, actual);
    }
}

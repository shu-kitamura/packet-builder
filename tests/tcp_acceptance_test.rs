use packet_builder::transport::tcp::{TcpPacket, header::TcpFlags, options::TcpOption};

#[test]
fn test_rfc9293_acceptance_criteria() {
    // Test all 8 IANA header flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    let mut flags = TcpFlags::new();

    // Test individual flags
    flags.cwr = true;
    assert_eq!(0x80, flags.to_u16());

    flags = TcpFlags::new();
    flags.ece = true;
    assert_eq!(0x40, flags.to_u16());

    flags = TcpFlags::new();
    flags.urg = true;
    assert_eq!(0x20, flags.to_u16());

    flags = TcpFlags::new();
    flags.ack = true;
    assert_eq!(0x10, flags.to_u16());

    flags = TcpFlags::new();
    flags.psh = true;
    assert_eq!(0x08, flags.to_u16());

    flags = TcpFlags::new();
    flags.rst = true;
    assert_eq!(0x04, flags.to_u16());

    flags = TcpFlags::new();
    flags.syn = true;
    assert_eq!(0x02, flags.to_u16());

    flags = TcpFlags::new();
    flags.fin = true;
    assert_eq!(0x01, flags.to_u16());

    // Test all three options: EOL, NOP, MSS
    let eol_option = TcpOption::EndOfOptionList;
    assert_eq!(0, eol_option.kind());
    assert_eq!(vec![0], eol_option.to_bytes());

    let nop_option = TcpOption::NoOperation;
    assert_eq!(1, nop_option.kind());
    assert_eq!(vec![1], nop_option.to_bytes());

    let mss_option = TcpOption::MaximumSegmentSize(1460);
    assert_eq!(2, mss_option.kind());
    assert_eq!(vec![2, 4, 0x05, 0xb4], mss_option.to_bytes());

    // Test SYN+MSS scenario matching expected byte sequence
    let payload = b"";
    let mut packet = TcpPacket::new(12345, 80, payload);

    packet.header.flags.syn = true;
    packet.header.sequence_number = 0x12345678;
    packet.header.window = 65535;
    packet.options.add(TcpOption::MaximumSegmentSize(1460));

    // Generate packet for IPv4
    let src_ip = [192, 168, 1, 100];
    let dst_ip = [192, 168, 1, 1];
    let packet_bytes = packet.to_bytes_ipv4(src_ip, dst_ip);

    // Verify correct header size and data_offset calculation
    assert_eq!(24, packet_bytes.len()); // 20-byte header + 4-byte option
    assert_eq!(0x60, packet_bytes[12]); // Data offset = 6 (24 bytes / 4)

    // Verify SYN flag is correctly set
    assert_eq!(0x02, packet_bytes[13]);

    // Verify MSS option is correctly placed and formatted
    assert_eq!(0x02, packet_bytes[20]); // MSS kind
    assert_eq!(0x04, packet_bytes[21]); // MSS length
    assert_eq!(0x05, packet_bytes[22]); // MSS value high byte
    assert_eq!(0xb4, packet_bytes[23]); // MSS value low byte (1460 = 0x05B4)

    // Verify checksum is calculated (non-zero)
    let checksum = u16::from_be_bytes([packet_bytes[16], packet_bytes[17]]);
    assert_ne!(0, checksum);

    // Test IPv6 checksum calculation
    let mut packet_ipv6 = TcpPacket::new(80, 443, b"test");
    packet_ipv6.header.flags.syn = true;

    let src_ipv6 = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let dst_ipv6 = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    let checksum_ipv6 = packet_ipv6.calculate_checksum_ipv6(src_ipv6, dst_ipv6);
    assert_ne!(0, checksum_ipv6);
}

// Create an extern crate alloc statement for the Vec macro
extern crate alloc;
use alloc::vec;

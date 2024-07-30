//! Parsing and building of IPv4, ICMP, UDP and TCP packets, plus the
//! internet checksum. Everything is plain byte slices, no unsafe code.

use std::fmt;

/// The one's complement sum used by IPv4, ICMP, UDP and TCP.
pub fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None; // odd byte left over from a previous chunk
    for chunk in chunks {
        let mut bytes = chunk.iter();
        if let Some(high) = carry.take() {
            let low = *bytes.next().unwrap_or(&0);
            sum += u32::from(u16::from_be_bytes([high, low]));
        }
        let rest = bytes.as_slice();
        let mut i = 0;
        while i + 1 < rest.len() {
            sum += u32::from(u16::from_be_bytes([rest[i], rest[i + 1]]));
            i += 2;
        }
        if i < rest.len() {
            carry = Some(rest[i]);
        }
    }
    if let Some(high) = carry {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut out = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            out[i] = p.parse().ok()?;
        }
        Some(Ipv4Addr(out))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parses an IPv4 header, verifying version, length and checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 {
            return Err("ipv4: too short");
        }
        if bytes[0] >> 4 != 4 {
            return Err("ipv4: not version 4");
        }
        let ihl = usize::from(bytes[0] & 0xF) * 4;
        if ihl < 20 || bytes.len() < ihl {
            return Err("ipv4: bad header length");
        }
        let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total < ihl || total > bytes.len() {
            return Err("ipv4: bad total length");
        }
        let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        if flags_frag & 0x1FFF != 0 || flags_frag & 0x2000 != 0 {
            return Err("ipv4: fragments are not supported");
        }
        if checksum(&[&bytes[..ihl]]) != 0 {
            return Err("ipv4: bad checksum");
        }
        Ok(Ipv4Packet {
            src: Ipv4Addr([bytes[12], bytes[13], bytes[14], bytes[15]]),
            dst: Ipv4Addr([bytes[16], bytes[17], bytes[18], bytes[19]]),
            protocol: bytes[9],
            ttl: bytes[8],
            payload: &bytes[ihl..total],
        })
    }

    /// Builds a packet with a 20-byte header around the payload.
    pub fn build(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut out = Vec::with_capacity(total);
        out.push(0x45);
        out.push(0);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]); // identification
        out.extend_from_slice(&[0x40, 0]); // don't fragment
        out.push(64); // ttl
        out.push(protocol);
        out.extend_from_slice(&[0, 0]); // checksum placeholder
        out.extend_from_slice(&src.0);
        out.extend_from_slice(&dst.0);
        let sum = checksum(&[&out[..20]]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }
}

/// The 12-byte pseudo header TCP and UDP include in their checksums.
fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, len: usize) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[..4].copy_from_slice(&src.0);
    p[4..8].copy_from_slice(&dst.0);
    p[9] = protocol;
    p[10..12].copy_from_slice(&(len as u16).to_be_bytes());
    p
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp<'a> {
    pub kind: u8,
    pub code: u8,
    pub rest: &'a [u8], // identifier + sequence for echo
    pub payload: &'a [u8],
}

impl<'a> Icmp<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("icmp: too short");
        }
        if checksum(&[bytes]) != 0 {
            return Err("icmp: bad checksum");
        }
        Ok(Icmp {
            kind: bytes[0],
            code: bytes[1],
            rest: &bytes[4..8],
            payload: &bytes[8..],
        })
    }

    pub fn build(kind: u8, code: u8, rest: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, code, 0, 0];
        out.extend_from_slice(rest);
        out.extend_from_slice(payload);
        let sum = checksum(&[&out]);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("udp: too short");
        }
        let len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if len < 8 || len > bytes.len() {
            return Err("udp: bad length");
        }
        let sum = u16::from_be_bytes([bytes[6], bytes[7]]);
        if sum != 0 && checksum(&[&pseudo_header(src, dst, PROTO_UDP, len), &bytes[..len]]) != 0 {
            return Err("udp: bad checksum");
        }
        Ok(Udp {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            payload: &bytes[8..len],
        })
    }

    pub fn build(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let len = 8 + payload.len();
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        let mut sum = checksum(&[&pseudo_header(src, dst, PROTO_UDP, len), &out]);
        if sum == 0 {
            sum = 0xFFFF;
        }
        out[6..8].copy_from_slice(&sum.to_be_bytes());
        out
    }
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(src: Ipv4Addr, dst: Ipv4Addr, bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 {
            return Err("tcp: too short");
        }
        let offset = usize::from(bytes[12] >> 4) * 4;
        if offset < 20 || offset > bytes.len() {
            return Err("tcp: bad data offset");
        }
        if checksum(&[&pseudo_header(src, dst, PROTO_TCP, bytes.len()), bytes]) != 0 {
            return Err("tcp: bad checksum");
        }
        Ok(TcpSegment {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: bytes[13],
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            payload: &bytes[offset..],
        })
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Builds a segment with a 20-byte header (an MSS option is added on SYNs).
    #[allow(clippy::too_many_arguments)]
    pub fn build(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, window: u16, payload: &[u8]) -> Vec<u8> {
        let options: &[u8] = if flags & SYN != 0 { &[2, 4, 0x04, 0xB0] } else { &[] }; // MSS 1200
        let header_len = 20 + options.len();
        let mut out = Vec::with_capacity(header_len + payload.len());
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ack.to_be_bytes());
        out.push(((header_len / 4) as u8) << 4);
        out.push(flags);
        out.extend_from_slice(&window.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
        out.extend_from_slice(options);
        out.extend_from_slice(payload);
        let sum = checksum(&[&pseudo_header(src, dst, PROTO_TCP, out.len()), &out]);
        out[16..18].copy_from_slice(&sum.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_rfc1071_example() {
        // the classic example from RFC 1071: 0x0001 0xf203 0xf4f5 0xf6f7 -> sum 0xddf2, checksum 0x220d
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&data]), 0x220d);
        assert_eq!(checksum(&[&data[..3], &data[3..]]), 0x220d, "chunk boundaries do not matter");
        assert_eq!(checksum(&[&[0x00, 0x01, 0xf2], &[0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), 0x220d);
    }

    #[test]
    fn ipv4_round_trip_and_validation() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let packet = Ipv4Packet::build(src, dst, PROTO_UDP, b"hello");
        let parsed = Ipv4Packet::parse(&packet).unwrap();
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.protocol, PROTO_UDP);
        assert_eq!(parsed.payload, b"hello");
        assert_eq!(checksum(&[&packet[..20]]), 0, "header checksum verifies");
        let mut corrupted = packet.clone();
        corrupted[15] ^= 1;
        assert_eq!(Ipv4Packet::parse(&corrupted), Err("ipv4: bad checksum"));
        assert!(Ipv4Packet::parse(&packet[..10]).is_err());
        assert_eq!(Ipv4Addr::parse("192.168.1.10"), Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(Ipv4Addr::parse("1.2.3"), None);
        assert_eq!(dst.to_string(), "10.0.0.2");
    }

    #[test]
    fn icmp_udp_tcp_round_trips() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let icmp = Icmp::build(8, 0, &[1, 2, 3, 4], b"ping");
        let parsed = Icmp::parse(&icmp).unwrap();
        assert_eq!(
            (parsed.kind, parsed.code, parsed.rest, parsed.payload),
            (8, 0, &[1u8, 2, 3, 4][..], &b"ping"[..])
        );

        let udp = Udp::build(src, dst, 1234, 7, b"echo me");
        let parsed = Udp::parse(src, dst, &udp).unwrap();
        assert_eq!((parsed.src_port, parsed.dst_port, parsed.payload), (1234, 7, &b"echo me"[..]));
        let other = Ipv4Addr::new(10, 0, 0, 3);
        assert_eq!(Udp::parse(src, other, &udp), Err("udp: bad checksum"), "pseudo header is part of the checksum");

        let tcp = TcpSegment::build(src, dst, 40000, 80, 1000, 2000, SYN | ACK, 65535, b"");
        let parsed = TcpSegment::parse(src, dst, &tcp).unwrap();
        assert_eq!((parsed.src_port, parsed.dst_port, parsed.seq, parsed.ack), (40000, 80, 1000, 2000));
        assert!(parsed.has(SYN) && parsed.has(ACK) && !parsed.has(FIN));
        assert_eq!(tcp.len(), 24, "syn carries the mss option");
        let data = TcpSegment::build(src, dst, 1, 2, 3, 4, ACK | PSH, 100, b"payload");
        assert_eq!(TcpSegment::parse(src, dst, &data).unwrap().payload, b"payload");
    }
}

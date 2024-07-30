//! The network stack: takes raw IPv4 packets, demultiplexes them to ICMP,
//! UDP and TCP, and returns the packets to send. Pure and testable; the TUN
//! device is wired up in `main.rs`.

use crate::packet::*;
use crate::tcp::{Connection, Echo, Http, Service, State};
use std::collections::HashMap;

pub struct Stack {
    pub addr: Ipv4Addr,
    connections: HashMap<(Ipv4Addr, u16, u16), Connection>,
    listeners: HashMap<u16, fn() -> Box<dyn Service>>,
    udp_echo_ports: Vec<u16>,
    iss: u32,
    pub log: Vec<String>,
}

impl Stack {
    pub fn new(addr: Ipv4Addr) -> Self {
        let mut listeners: HashMap<u16, fn() -> Box<dyn Service>> = HashMap::new();
        listeners.insert(7, || Box::new(Echo));
        listeners.insert(80, || Box::new(Http::new()));
        listeners.insert(8080, || Box::new(Http::new()));
        Stack {
            addr,
            connections: HashMap::new(),
            listeners,
            udp_echo_ports: vec![7],
            iss: 0x1000,
            log: Vec::new(),
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn connection_state(&self, remote: Ipv4Addr, remote_port: u16, local_port: u16) -> Option<State> {
        self.connections.get(&(remote, remote_port, local_port)).map(|c| c.state)
    }

    /// Processes one IPv4 packet from the wire; returns packets to transmit.
    pub fn handle(&mut self, bytes: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        let packet = match Ipv4Packet::parse(bytes) {
            Ok(p) => p,
            Err(e) => {
                self.log.push(format!("dropped: {e}"));
                return Vec::new();
            }
        };
        if packet.dst != self.addr {
            return Vec::new();
        }
        match packet.protocol {
            PROTO_ICMP => self.handle_icmp(&packet),
            PROTO_UDP => self.handle_udp(&packet),
            PROTO_TCP => self.handle_tcp(&packet, now_ms),
            other => {
                self.log.push(format!("unsupported protocol {other}"));
                Vec::new()
            }
        }
    }

    fn handle_icmp(&mut self, packet: &Ipv4Packet) -> Vec<Vec<u8>> {
        match Icmp::parse(packet.payload) {
            Ok(icmp) if icmp.kind == 8 && icmp.code == 0 => {
                self.log.push(format!("ping from {}", packet.src));
                let mut rest = [0u8; 4];
                rest.copy_from_slice(icmp.rest);
                let reply = Icmp::build(0, 0, &rest, icmp.payload);
                vec![Ipv4Packet::build(self.addr, packet.src, PROTO_ICMP, &reply)]
            }
            Ok(_) => Vec::new(),
            Err(e) => {
                self.log.push(format!("dropped: {e}"));
                Vec::new()
            }
        }
    }

    fn handle_udp(&mut self, packet: &Ipv4Packet) -> Vec<Vec<u8>> {
        match Udp::parse(packet.src, packet.dst, packet.payload) {
            Ok(udp) if self.udp_echo_ports.contains(&udp.dst_port) => {
                let reply = Udp::build(self.addr, packet.src, udp.dst_port, udp.src_port, udp.payload);
                vec![Ipv4Packet::build(self.addr, packet.src, PROTO_UDP, &reply)]
            }
            Ok(udp) => {
                // port unreachable: ICMP type 3 code 3 with the original header
                let mut original = Vec::new();
                original.extend_from_slice(&Ipv4Packet::build(
                    packet.src,
                    packet.dst,
                    PROTO_UDP,
                    &packet.payload[..8.min(packet.payload.len())],
                ));
                let reply = Icmp::build(3, 3, &[0, 0, 0, 0], &original[..original.len().min(28)]);
                self.log.push(format!("udp to closed port {}", udp.dst_port));
                vec![Ipv4Packet::build(self.addr, packet.src, PROTO_ICMP, &reply)]
            }
            Err(e) => {
                self.log.push(format!("dropped: {e}"));
                Vec::new()
            }
        }
    }

    fn handle_tcp(&mut self, packet: &Ipv4Packet, now_ms: u64) -> Vec<Vec<u8>> {
        let seg = match TcpSegment::parse(packet.src, packet.dst, packet.payload) {
            Ok(s) => s,
            Err(e) => {
                self.log.push(format!("dropped: {e}"));
                return Vec::new();
            }
        };
        let key = (packet.src, seg.src_port, seg.dst_port);
        if !self.connections.contains_key(&key) {
            match self.listeners.get(&seg.dst_port) {
                Some(factory) if seg.has(SYN) && !seg.has(ACK) => {
                    self.iss = self.iss.wrapping_mul(1103515245).wrapping_add(12345);
                    let conn = Connection::new((self.addr, seg.dst_port), (packet.src, seg.src_port), self.iss, factory());
                    self.connections.insert(key, conn);
                    self.log
                        .push(format!("connection from {}:{} to port {}", packet.src, seg.src_port, seg.dst_port));
                }
                _ => {
                    if seg.has(RST) {
                        return Vec::new();
                    }
                    // nobody listening: reset
                    let (seq, ack, flags) = if seg.has(ACK) {
                        (seg.ack, 0, RST)
                    } else {
                        (0, seg.seq.wrapping_add(seg.payload.len() as u32 + 1), RST | ACK)
                    };
                    let rst = TcpSegment::build(self.addr, packet.src, seg.dst_port, seg.src_port, seq, ack, flags, 0, &[]);
                    return vec![Ipv4Packet::build(self.addr, packet.src, PROTO_TCP, &rst)];
                }
            }
        }
        let conn = self.connections.get_mut(&key).expect("just inserted");
        let outgoing = conn.on_segment(&seg, now_ms);
        let packets = outgoing.into_iter().map(|o| self.wrap(packet.src, seg.src_port, seg.dst_port, o)).collect();
        if self.connections[&key].is_closed() {
            self.connections.remove(&key);
        }
        packets
    }

    fn wrap(&self, remote: Ipv4Addr, remote_port: u16, local_port: u16, o: crate::tcp::Outgoing) -> Vec<u8> {
        let seg = TcpSegment::build(self.addr, remote, local_port, remote_port, o.seq, o.ack, o.flags, 16384, &o.payload);
        Ipv4Packet::build(self.addr, remote, PROTO_TCP, &seg)
    }

    /// Runs timers on every connection (call every ~100 ms).
    pub fn tick(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let keys: Vec<_> = self.connections.keys().copied().collect();
        for key in keys {
            let outgoing = self.connections.get_mut(&key).unwrap().tick(now_ms);
            for o in outgoing {
                packets.push(self.wrap(key.0, key.1, key.2, o));
            }
            if self.connections[&key].is_closed() {
                self.connections.remove(&key);
            }
        }
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr([10, 0, 0, 1]);
    const US: Ipv4Addr = Ipv4Addr([10, 0, 0, 2]);

    #[test]
    fn answers_pings() {
        let mut s = Stack::new(US);
        let request = Icmp::build(8, 0, &[0xAB, 0xCD, 0, 1], b"abcdefgh");
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_ICMP, &request), 0);
        assert_eq!(out.len(), 1);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        assert_eq!((ip.src, ip.dst, ip.protocol), (US, HOST, PROTO_ICMP));
        let reply = Icmp::parse(ip.payload).unwrap();
        assert_eq!((reply.kind, reply.rest, reply.payload), (0, &[0xAB, 0xCD, 0, 1][..], &b"abcdefgh"[..]));
        // packets for other hosts and corrupt packets are ignored
        assert!(s
            .handle(&Ipv4Packet::build(HOST, Ipv4Addr::new(10, 0, 0, 9), PROTO_ICMP, &request), 0)
            .is_empty());
        assert!(s.handle(b"garbage", 0).is_empty());
    }

    #[test]
    fn udp_echo_and_port_unreachable() {
        let mut s = Stack::new(US);
        let dgram = Udp::build(HOST, US, 4444, 7, b"echo");
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_UDP, &dgram), 0);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        let udp = Udp::parse(ip.src, ip.dst, ip.payload).unwrap();
        assert_eq!((udp.src_port, udp.dst_port, udp.payload), (7, 4444, &b"echo"[..]));
        let closed = Udp::build(HOST, US, 4444, 9999, b"x");
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_UDP, &closed), 0);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        assert_eq!(ip.protocol, PROTO_ICMP);
        let icmp = Icmp::parse(ip.payload).unwrap();
        assert_eq!((icmp.kind, icmp.code), (3, 3));
    }

    /// Drives a full TCP exchange through the stack as a client would.
    #[test]
    fn tcp_echo_through_the_stack() {
        let mut s = Stack::new(US);
        let syn = TcpSegment::build(HOST, US, 5555, 7, 100, 0, SYN, 65535, &[]);
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &syn), 0);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        let syn_ack = TcpSegment::parse(ip.src, ip.dst, ip.payload).unwrap();
        assert!(syn_ack.has(SYN) && syn_ack.has(ACK));
        assert_eq!(syn_ack.ack, 101);
        let iss = syn_ack.seq;
        assert_eq!(s.connection_state(HOST, 5555, 7), Some(State::SynReceived));

        let ack = TcpSegment::build(HOST, US, 5555, 7, 101, iss + 1, ACK, 65535, &[]);
        assert!(s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &ack), 1).is_empty());
        assert_eq!(s.connection_state(HOST, 5555, 7), Some(State::Established));

        let data = TcpSegment::build(HOST, US, 5555, 7, 101, iss + 1, ACK | PSH, 65535, b"ping");
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &data), 2);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        let echo = TcpSegment::parse(ip.src, ip.dst, ip.payload).unwrap();
        assert_eq!(echo.payload, b"ping");
        assert_eq!((echo.seq, echo.ack), (iss + 1, 105));

        // close from the client side
        let fin = TcpSegment::build(HOST, US, 5555, 7, 105, iss + 5, ACK | FIN, 65535, &[]);
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &fin), 3);
        let last = TcpSegment::parse(US, HOST, Ipv4Packet::parse(out.last().unwrap()).unwrap().payload).unwrap();
        assert!(last.has(FIN));
        let final_ack = TcpSegment::build(HOST, US, 5555, 7, 106, last.seq + 1, ACK, 65535, &[]);
        s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &final_ack), 4);
        assert_eq!(s.connection_count(), 0, "closed connection is removed");
    }

    #[test]
    fn closed_ports_get_a_reset() {
        let mut s = Stack::new(US);
        let syn = TcpSegment::build(HOST, US, 5555, 9999, 100, 0, SYN, 65535, &[]);
        let out = s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &syn), 0);
        let ip = Ipv4Packet::parse(&out[0]).unwrap();
        let rst = TcpSegment::parse(ip.src, ip.dst, ip.payload).unwrap();
        assert!(rst.has(RST) && rst.has(ACK));
        assert_eq!(rst.ack, 101);
        assert_eq!(s.connection_count(), 0);
    }

    #[test]
    fn stack_tick_retransmits() {
        let mut s = Stack::new(US);
        let syn = TcpSegment::build(HOST, US, 5555, 7, 100, 0, SYN, 65535, &[]);
        s.handle(&Ipv4Packet::build(HOST, US, PROTO_TCP, &syn), 0);
        assert!(s.tick(100).is_empty());
        let out = s.tick(1500);
        assert_eq!(out.len(), 1, "the SYN-ACK is retransmitted when the client never answers");
    }
}

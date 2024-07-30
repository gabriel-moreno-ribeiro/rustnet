//! A small TCP implementation: passive open, the three-way handshake,
//! ordered delivery with cumulative acknowledgements, retransmission on
//! timeout, and both sides of connection teardown. Applications plug in as
//! a `Service` that receives bytes and may send bytes or close.

use crate::packet::{Ipv4Addr, TcpSegment, ACK, FIN, PSH, RST, SYN};
use std::collections::VecDeque;

pub const MSS: usize = 1200;
const WINDOW: u16 = 16384;
const RTO_MS: u64 = 1000;
const TIME_WAIT_MS: u64 = 2000;
const MAX_RETRIES: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Listen,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    Closed,
}

/// What a listening port does with a connection.
pub trait Service {
    /// Called with bytes received in order. Returns bytes to send back and
    /// whether the connection should be closed after they are sent.
    fn on_data(&mut self, data: &[u8]) -> (Vec<u8>, bool);
    /// Called when the peer closes its side. Returns final bytes to send.
    fn on_peer_close(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

/// Echoes everything back.
pub struct Echo;
impl Service for Echo {
    fn on_data(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        (data.to_vec(), false)
    }
}

/// Answers any HTTP request with a small page, then closes.
pub struct Http {
    request: Vec<u8>,
}
impl Http {
    pub fn new() -> Self {
        Http { request: Vec::new() }
    }
}
impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}
impl Service for Http {
    fn on_data(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        self.request.extend_from_slice(data);
        if !self.request.windows(4).any(|w| w == b"\r\n\r\n") {
            return (Vec::new(), false);
        }
        let first_line = String::from_utf8_lossy(&self.request).lines().next().unwrap_or("").to_string();
        let body = format!("<html><body><h1>hello from rustnet</h1><p>you asked for: {}</p></body></html>\n", first_line);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        (response.into_bytes(), true)
    }
}

pub struct Connection {
    pub state: State,
    pub local: (Ipv4Addr, u16),
    pub remote: (Ipv4Addr, u16),
    // send side
    snd_una: u32,
    snd_nxt: u32,
    unacked: VecDeque<(u32, Vec<u8>, u8)>, // (seq, data, flags) segments in flight
    send_queue: Vec<u8>,                   // application data not yet segmented
    fin_pending: bool,
    // receive side
    rcv_nxt: u32,
    peer_window: u16,
    // timers
    last_send_ms: u64,
    retries: u32,
    time_wait_started: u64,
    service: Box<dyn Service>,
}

/// Outgoing segment produced by the state machine (headers filled by the stack).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Outgoing {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

fn wrapping_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

impl Connection {
    pub fn new(local: (Ipv4Addr, u16), remote: (Ipv4Addr, u16), iss: u32, service: Box<dyn Service>) -> Self {
        Connection {
            state: State::Listen,
            local,
            remote,
            snd_una: iss,
            snd_nxt: iss,
            unacked: VecDeque::new(),
            send_queue: Vec::new(),
            fin_pending: false,
            rcv_nxt: 0,
            peer_window: WINDOW,
            last_send_ms: 0,
            retries: 0,
            time_wait_started: 0,
            service,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    fn segment(&self, seq: u32, flags: u8, payload: Vec<u8>) -> Outgoing {
        Outgoing {
            seq,
            ack: self.rcv_nxt,
            flags: flags | ACK,
            payload,
        }
    }

    fn ack_only(&self) -> Outgoing {
        self.segment(self.snd_nxt, 0, Vec::new())
    }

    /// Handles one incoming segment; returns segments to send.
    pub fn on_segment(&mut self, seg: &TcpSegment, now_ms: u64) -> Vec<Outgoing> {
        let mut out = Vec::new();
        if seg.has(RST) {
            self.state = State::Closed;
            return out;
        }
        match self.state {
            State::Listen => {
                if seg.has(SYN) {
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.peer_window = seg.window;
                    let syn_ack = self.segment(self.snd_nxt, SYN, Vec::new());
                    self.unacked.push_back((self.snd_nxt, Vec::new(), SYN));
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.last_send_ms = now_ms;
                    self.state = State::SynReceived;
                    out.push(syn_ack);
                }
                return out;
            }
            State::Closed => return out,
            _ => {}
        }

        // acknowledgement processing (all states after Listen)
        if seg.has(ACK) {
            self.process_ack(seg.ack);
            self.peer_window = seg.window;
            if self.state == State::SynReceived && self.snd_una == self.snd_nxt {
                self.state = State::Established;
            }
            if self.state == State::FinWait1 && self.unacked.is_empty() && !self.fin_pending {
                self.state = State::FinWait2;
            }
            if self.state == State::Closing && self.unacked.is_empty() {
                self.state = State::TimeWait;
                self.time_wait_started = now_ms;
            }
            if self.state == State::LastAck && self.unacked.is_empty() {
                self.state = State::Closed;
                return out;
            }
        }

        // data: only in-order segments are consumed; anything else is re-acked
        let mut need_ack = false;
        if !seg.payload.is_empty() {
            if seg.seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                if matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) {
                    let (reply, close) = self.service.on_data(seg.payload);
                    self.send_queue.extend_from_slice(&reply);
                    if close {
                        self.fin_pending = true;
                    }
                }
            }
            need_ack = true;
        }

        // peer's FIN
        if seg.has(FIN) && seg.seq.wrapping_add(seg.payload.len() as u32) == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            need_ack = true;
            match self.state {
                State::Established | State::SynReceived => {
                    let reply = self.service.on_peer_close();
                    self.send_queue.extend_from_slice(&reply);
                    self.fin_pending = true; // we close too once our data is out
                    self.state = State::CloseWait;
                }
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.time_wait_started = now_ms;
                }
                _ => {}
            }
        }

        out.extend(self.flush(now_ms));
        if need_ack && !out.iter().any(|o| !o.payload.is_empty() || o.flags & FIN != 0) {
            out.push(self.ack_only());
        }
        out
    }

    fn process_ack(&mut self, ack: u32) {
        if wrapping_lt(self.snd_una, ack) && !wrapping_lt(self.snd_nxt, ack) {
            self.snd_una = ack;
            self.retries = 0;
            while let Some((seq, data, flags)) = self.unacked.front() {
                let len = data.len() as u32 + u32::from(flags & (SYN | FIN) != 0);
                if !wrapping_lt(ack, seq.wrapping_add(len)) {
                    self.unacked.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// Turns queued application data (and a pending FIN) into segments.
    fn flush(&mut self, now_ms: u64) -> Vec<Outgoing> {
        let mut out = Vec::new();
        if !matches!(self.state, State::Established | State::CloseWait | State::FinWait1 | State::FinWait2) {
            return out;
        }
        let in_flight: usize = self.unacked.iter().map(|(_, d, _)| d.len()).sum();
        let mut budget = usize::from(self.peer_window).saturating_sub(in_flight);
        while !self.send_queue.is_empty() && budget > 0 {
            let n = self.send_queue.len().min(MSS).min(budget);
            let data: Vec<u8> = self.send_queue.drain(..n).collect();
            let flags = if self.send_queue.is_empty() { PSH } else { 0 };
            out.push(self.segment(self.snd_nxt, flags, data.clone()));
            self.unacked.push_back((self.snd_nxt, data, flags));
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
            budget -= n;
            self.last_send_ms = now_ms;
        }
        if self.fin_pending && self.send_queue.is_empty() && matches!(self.state, State::Established | State::CloseWait) {
            out.push(self.segment(self.snd_nxt, FIN, Vec::new()));
            self.unacked.push_back((self.snd_nxt, Vec::new(), FIN));
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_pending = false;
            self.last_send_ms = now_ms;
            self.state = if self.state == State::CloseWait { State::LastAck } else { State::FinWait1 };
        }
        out
    }

    /// Periodic maintenance: retransmit the oldest unacknowledged segment
    /// after the timeout, give up after too many tries, leave TIME-WAIT.
    pub fn tick(&mut self, now_ms: u64) -> Vec<Outgoing> {
        let mut out = Vec::new();
        if self.state == State::TimeWait && now_ms.saturating_sub(self.time_wait_started) >= TIME_WAIT_MS {
            self.state = State::Closed;
            return out;
        }
        if let Some((seq, data, flags)) = self.unacked.front() {
            if now_ms.saturating_sub(self.last_send_ms) >= RTO_MS {
                if self.retries >= MAX_RETRIES {
                    self.state = State::Closed;
                    return out;
                }
                self.retries += 1;
                self.last_send_ms = now_ms;
                out.push(self.segment(*seq, *flags | if !data.is_empty() { PSH } else { 0 }, data.clone()));
            }
        }
        out.extend(self.flush(now_ms));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> TcpSegment<'_> {
        TcpSegment {
            src_port: 5000,
            dst_port: 80,
            seq,
            ack,
            flags,
            window: 65535,
            payload,
        }
    }

    fn conn(service: Box<dyn Service>) -> Connection {
        Connection::new((Ipv4Addr::new(10, 0, 0, 2), 80), (Ipv4Addr::new(10, 0, 0, 1), 5000), 1000, service)
    }

    fn handshake(c: &mut Connection) {
        let out = c.on_segment(&seg(500, 0, SYN, b""), 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].flags, SYN | ACK);
        assert_eq!((out[0].seq, out[0].ack), (1000, 501));
        assert_eq!(c.state, State::SynReceived);
        let out = c.on_segment(&seg(501, 1001, ACK, b""), 0);
        assert!(out.is_empty());
        assert_eq!(c.state, State::Established);
    }

    #[test]
    fn three_way_handshake_then_echo() {
        let mut c = conn(Box::new(Echo));
        handshake(&mut c);
        let out = c.on_segment(&seg(501, 1001, ACK | PSH, b"hello"), 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"hello");
        assert_eq!((out[0].seq, out[0].ack), (1001, 506));
        assert!(out[0].flags & ACK != 0 && out[0].flags & PSH != 0);
        // the peer acknowledges our echo: nothing left in flight
        let out = c.on_segment(&seg(506, 1006, ACK, b""), 20);
        assert!(out.is_empty());
        assert!(c.unacked.is_empty());
    }

    #[test]
    fn out_of_order_data_is_reacked_not_consumed() {
        let mut c = conn(Box::new(Echo));
        handshake(&mut c);
        let out = c.on_segment(&seg(600, 1001, ACK | PSH, b"future"), 10);
        assert_eq!(out.len(), 1);
        assert!(out[0].payload.is_empty());
        assert_eq!(out[0].ack, 501, "still waiting for byte 501");
        let out = c.on_segment(&seg(501, 1001, ACK | PSH, b"now"), 11);
        assert_eq!(out[0].payload, b"now");
    }

    #[test]
    fn retransmits_unacked_data_and_gives_up_eventually() {
        let mut c = conn(Box::new(Echo));
        handshake(&mut c);
        c.on_segment(&seg(501, 1001, ACK | PSH, b"abc"), 0);
        assert!(c.tick(500).is_empty(), "before the timeout nothing happens");
        let out = c.tick(1000);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].seq, &out[0].payload[..]), (1001, &b"abc"[..]));
        for i in 1..=MAX_RETRIES {
            let _ = c.tick(1000 + u64::from(i) * 1000);
        }
        assert_eq!(c.state, State::Closed, "after too many retries the connection is dropped");
    }

    #[test]
    fn peer_closes_first() {
        let mut c = conn(Box::new(Echo));
        handshake(&mut c);
        let out = c.on_segment(&seg(501, 1001, ACK | FIN, b""), 0);
        // we ack the FIN and, having nothing to send, send our own FIN
        assert!(out.iter().any(|o| o.flags & FIN != 0));
        assert_eq!(out.last().unwrap().ack, 502);
        assert_eq!(c.state, State::LastAck);
        let out = c.on_segment(&seg(502, 1002, ACK, b""), 0);
        assert!(out.is_empty());
        assert_eq!(c.state, State::Closed);
    }

    #[test]
    fn http_service_answers_and_closes_first() {
        let mut c = conn(Box::new(Http::new()));
        handshake(&mut c);
        let out = c.on_segment(&seg(501, 1001, ACK | PSH, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 0);
        let data: Vec<u8> = out.iter().flat_map(|o| o.payload.clone()).collect();
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("GET / HTTP/1.1"));
        assert!(out.last().unwrap().flags & FIN != 0, "FIN follows the response");
        assert_eq!(c.state, State::FinWait1);
        let fin_seq = out.last().unwrap().seq;
        // peer acks everything including our FIN, then closes
        let out = c.on_segment(&seg(528, fin_seq + 1, ACK, b""), 0);
        assert!(out.is_empty());
        assert_eq!(c.state, State::FinWait2);
        let out = c.on_segment(&seg(528, fin_seq + 1, ACK | FIN, b""), 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ack, 529);
        assert_eq!(c.state, State::TimeWait);
        assert!(c.tick(5000).is_empty());
        assert_eq!(c.state, State::Closed);
    }

    #[test]
    fn large_replies_are_segmented_by_mss_and_window() {
        struct Big;
        impl Service for Big {
            fn on_data(&mut self, _: &[u8]) -> (Vec<u8>, bool) {
                (vec![7u8; 3000], false)
            }
        }
        let mut c = conn(Box::new(Big));
        handshake(&mut c);
        let out = c.on_segment(&seg(501, 1001, ACK | PSH, b"x"), 0);
        let sizes: Vec<usize> = out.iter().map(|o| o.payload.len()).collect();
        assert_eq!(sizes, vec![1200, 1200, 600]);
        assert!(out[2].flags & PSH != 0);
        assert_eq!(out[1].seq, 1001 + 1200);
    }

    #[test]
    fn reset_closes_and_syn_on_established_is_ignored() {
        let mut c = conn(Box::new(Echo));
        handshake(&mut c);
        assert!(c.on_segment(&seg(501, 1001, SYN, b""), 0).is_empty());
        assert_eq!(c.state, State::Established);
        c.on_segment(&seg(501, 1001, RST, b""), 0);
        assert_eq!(c.state, State::Closed);
    }
}

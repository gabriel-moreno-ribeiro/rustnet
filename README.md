# rustnet

A TCP/IP stack written from scratch in Rust, running in userspace on a Linux
TUN device: IPv4, ICMP echo, UDP, and a TCP implementation with the
three-way handshake, ordered delivery, retransmission and connection
teardown. It serves a TCP echo service and a tiny HTTP server, so `ping`,
`nc` and `curl` on the host talk to code that contains no kernel networking
at all. Zero dependencies.

```sh
cargo build --release
sudo ./target/release/rustnet            # creates tun0: host 10.0.0.1, stack 10.0.0.2

ping 10.0.0.2
echo hi | nc -u -w1 10.0.0.2 7
nc 10.0.0.2 7
curl http://10.0.0.2/
```

## How it works

- **TUN** (`src/tun.rs`): `/dev/net/tun` is opened and configured with the
  `TUNSETIFF` ioctl (declared by hand, no libc crate). Every IP packet the
  host sends to 10.0.0.2 arrives as bytes on that file descriptor; whatever
  we write back is delivered to the host as if it came from the network.
- **Packets** (`src/packet.rs`): parsers and builders for IPv4, ICMP, UDP
  and TCP headers with the one's-complement checksum, including the TCP and
  UDP pseudo header. Bad checksums, fragments and truncated packets are
  rejected.
- **Stack** (`src/stack.rs`): demultiplexes by protocol and port. ICMP echo
  requests get replies; UDP port 7 echoes and other ports get an ICMP port
  unreachable; TCP SYNs to listening ports create connections, anything
  else gets a RST.
- **TCP** (`src/tcp.rs`): each connection is a state machine (LISTEN,
  SYN-RECEIVED, ESTABLISHED, CLOSE-WAIT, LAST-ACK, FIN-WAIT-1/2, CLOSING,
  TIME-WAIT). Received data is accepted only in order (`seq == rcv.nxt`),
  everything else is re-acknowledged. Application replies are segmented to
  the MSS and the peer's window, kept in an unacknowledged queue, and
  retransmitted after a one second timeout until acknowledged (giving up
  after six tries). A pending FIN is sent once the send queue drains; the
  peer's FIN moves through CLOSE-WAIT/LAST-ACK or FIN-WAIT/TIME-WAIT
  depending on who closed first.
- **Services**: `Echo` returns what it receives; `Http` collects a request
  until the blank line, answers with a page, and closes.

## Tests

`cargo test` runs unit tests for checksums (RFC 1071 vector), every packet
codec, the TCP state machine (handshake, echo, out-of-order data,
retransmission and give-up, both close sequences, segmentation by MSS and
window, resets) and the stack's demultiplexing.

`sudo cargo test -- --include-ignored` additionally runs the end-to-end
test: it starts the stack on a TUN device and, with the real kernel as the
peer, checks `ping`, a UDP echo through a `UdpSocket`, a 5000-byte TCP echo
through a `TcpStream`, and `curl` fetching the HTTP page.

## License

MIT

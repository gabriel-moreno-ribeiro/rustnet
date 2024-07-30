//! End-to-end test against the real Linux kernel: starts the stack on a TUN
//! device and talks to it with the host's own sockets and tools. Needs root,
//! so it is ignored by default:  sudo cargo test -- --include-ignored
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_stack() -> Server {
    let bin = env!("CARGO_BIN_EXE_rustnet");
    let child = Command::new(bin)
        .args(["--iface", "tuntest0", "--addr", "10.77.0.2", "--host", "10.77.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .expect("start rustnet");
    thread::sleep(Duration::from_millis(800));
    Server(child)
}

#[test]
#[ignore]
fn kernel_talks_to_our_stack() {
    let _server = start_stack();

    // ICMP: the ping utility must get replies
    let ping = Command::new("ping").args(["-c", "3", "-W", "2", "10.77.0.2"]).output().expect("ping");
    let text = String::from_utf8_lossy(&ping.stdout);
    assert!(text.contains("3 received") || text.contains("3 packets received"), "ping output: {text}");

    // UDP echo through a kernel socket
    let udp = UdpSocket::bind("10.77.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    udp.send_to(b"udp hello", "10.77.0.2:7").unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = udp.recv_from(&mut buf).expect("udp echo reply");
    assert_eq!(&buf[..n], b"udp hello");

    // TCP echo: the kernel does the client side of the handshake for us
    let mut stream = TcpStream::connect_timeout(&"10.77.0.2:7".parse().unwrap(), Duration::from_secs(3)).expect("tcp connect");
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < payload.len() {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).expect("tcp echo data");
        assert!(n > 0);
        echoed.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(echoed, payload, "5000 bytes echoed back over our TCP");
    drop(stream);

    // HTTP with curl over our TCP implementation
    let curl = Command::new("curl")
        .args(["-s", "--max-time", "5", "http://10.77.0.2/"])
        .output()
        .expect("curl");
    let page = String::from_utf8_lossy(&curl.stdout);
    assert!(page.contains("hello from rustnet"), "curl output: {page}");
}

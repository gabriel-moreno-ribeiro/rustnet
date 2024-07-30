//! rustnet - a userspace TCP/IP stack on a TUN device.
//!
//!   sudo rustnet [--iface tun0] [--addr 10.0.0.2] [--host 10.0.0.1]
//!
//! Then, from another terminal:
//!   ping 10.0.0.2                 (ICMP echo)
//!   echo hi | nc -u -w1 10.0.0.2 7  (UDP echo)
//!   nc 10.0.0.2 7                 (TCP echo)
//!   curl http://10.0.0.2/         (HTTP over our own TCP)
use rustnet::packet::Ipv4Addr;
use rustnet::stack::Stack;
use rustnet::tun::Tun;
use std::process::Command;
use std::time::{Duration, Instant};

extern "C" {
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut iface = "tun0".to_string();
    let mut addr = "10.0.0.2".to_string();
    let mut host = "10.0.0.1".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iface" => iface = args.get(i + 1).cloned().unwrap_or(iface),
            "--addr" => addr = args.get(i + 1).cloned().unwrap_or(addr),
            "--host" => host = args.get(i + 1).cloned().unwrap_or(host),
            other => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    let our_addr = Ipv4Addr::parse(&addr).expect("bad --addr");

    let mut tun = match Tun::open(&iface) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot open TUN device {iface}: {e} (run as root)");
            std::process::exit(1);
        }
    };
    // give the host side an address and bring the interface up
    for cmd in [format!("ip addr add {host}/24 dev {}", tun.name), format!("ip link set {} up", tun.name)] {
        let status = Command::new("sh").arg("-c").arg(&cmd).status();
        if !matches!(status, Ok(s) if s.success()) {
            eprintln!("warning: '{cmd}' failed; configure the interface manually");
        }
    }
    println!(
        "rustnet: {} is up, we are {our_addr}, host is {host}. Try: ping {our_addr} | curl http://{our_addr}/ | nc {our_addr} 7",
        tun.name
    );

    let mut stack = Stack::new(our_addr);
    let start = Instant::now();
    let mut buf = vec![0u8; 65536];
    let mut last_tick = 0u64;
    loop {
        let mut fds = [PollFd {
            fd: tun.raw_fd(),
            events: 1,
            revents: 0,
        }];
        let ready = unsafe { poll(fds.as_mut_ptr(), 1, 100) };
        let now = start.elapsed().as_millis() as u64;
        if ready > 0 {
            match tun.recv(&mut buf) {
                Ok(n) => {
                    for packet in stack.handle(&buf[..n], now) {
                        if let Err(e) = tun.send(&packet) {
                            eprintln!("send failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("read failed: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        if now.saturating_sub(last_tick) >= 100 {
            last_tick = now;
            for packet in stack.tick(now) {
                let _ = tun.send(&packet);
            }
        }
        for line in stack.log.drain(..) {
            println!("{line}");
        }
    }
}

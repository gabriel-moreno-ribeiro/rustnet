//! A Linux TUN device opened with plain system calls (no crates): the
//! kernel hands us raw IP packets that the host routes to our address, and
//! whatever we write back is delivered to the host as if from the network.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETIFF: u64 = 0x4004_54ca;

extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

pub struct Tun {
    file: File,
    pub name: String,
}

impl Tun {
    /// Opens (creating if needed) the TUN interface with the given name.
    /// Needs CAP_NET_ADMIN, in practice: run as root.
    pub fn open(name: &str) -> io::Result<Tun> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
        // struct ifreq: 16 bytes of name followed by a union starting with the flags
        let mut ifr = [0u8; 40];
        let bytes = name.as_bytes();
        if bytes.len() >= 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
        }
        ifr[..bytes.len()].copy_from_slice(bytes);
        ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
        let rc = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = String::from_utf8_lossy(&ifr[..16]).trim_end_matches('\0').to_string();
        Ok(Tun { file, name: actual })
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    pub fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.file.write_all(packet)
    }

    pub fn raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

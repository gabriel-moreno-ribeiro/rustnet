# rustnet

> 🇺🇸 [English version below](#english)

Uma pilha TCP/IP em espaço de usuário, em Rust, rodando numa interface TUN do Linux: IPv4, ICMP echo, UDP e um TCP com handshake de três vias, entrega em ordem, retransmissão e encerramento. Serve um echo TCP e um servidor HTTP minúsculo, então `ping`, `nc` e `curl` da sua máquina conversam com código que não usa a rede do kernel pra nada. Zero dependências.

A frase que resume o projeto: o `curl` do Linux baixou uma página de um "servidor" que era um `Vec<u8>` sendo montado à mão, byte a byte, pelo meu código. Depois disso TCP parou de ser mágica.

```sh
cargo build --release
sudo ./target/release/rustnet            # cria tun0: host 10.0.0.1, pilha 10.0.0.2

ping 10.0.0.2
echo hi | nc -u -w1 10.0.0.2 7
nc 10.0.0.2 7
curl http://10.0.0.2/
```

## Camadas

- **TUN** (`src/tun.rs`): abre `/dev/net/tun` e configura com o ioctl `TUNSETIFF` (declarado na mão, sem crate libc). Todo pacote IP que o host manda pra 10.0.0.2 chega como bytes nesse descritor; o que a gente escreve de volta o host recebe como se tivesse vindo da rede.
- **Pacotes** (`src/packet.rs`): parsers e construtores de IPv4, ICMP, UDP e TCP com o checksum de complemento de um, incluindo o pseudo-header de TCP/UDP. Checksum errado, fragmento e pacote truncado são rejeitados.
- **Pilha** (`src/stack.rs`): demultiplexa por protocolo e porta. ICMP echo responde; UDP na porta 7 ecoa e nas outras devolve ICMP port unreachable; SYN em porta com serviço cria conexão, o resto leva RST.
- **TCP** (`src/tcp.rs`): cada conexão é uma máquina de estados (LISTEN, SYN-RECEIVED, ESTABLISHED, CLOSE-WAIT, LAST-ACK, FIN-WAIT-1/2, CLOSING, TIME-WAIT). Dados só são aceitos em ordem (`seq == rcv.nxt`); o resto é re-ACKado. As respostas da aplicação são segmentadas pelo MSS e pela janela do peer, ficam numa fila de não-confirmados e são retransmitidas a cada segundo até o ACK chegar (desistindo depois de seis tentativas). O FIN sai quando a fila esvazia, e o FIN do outro lado passa por CLOSE-WAIT/LAST-ACK ou FIN-WAIT/TIME-WAIT dependendo de quem fechou primeiro.
- **Serviços**: `Echo` devolve o que recebe; `Http` junta a requisição até a linha em branco, responde uma página e fecha.

## Testes

`cargo test` roda os testes unitários: checksums (o exemplo do RFC 1071), cada codec de pacote, a máquina de estados do TCP (handshake, echo, dados fora de ordem, retransmissão e desistência, os dois jeitos de fechar, segmentação por MSS e janela, RST) e o demux da pilha.

`sudo cargo test -- --include-ignored` roda o teste de ponta a ponta: sobe a pilha numa TUN e, com o kernel de verdade do outro lado, confere `ping`, echo UDP por um `UdpSocket`, echo TCP de 5000 bytes por um `TcpStream` e o `curl` pegando a página. O CI roda isso como root.

---

## English

A userspace TCP/IP stack, in Rust, running on a Linux TUN interface: IPv4, ICMP echo, UDP and a TCP with three-way handshake, in-order delivery, retransmission and teardown. It serves a TCP echo and a tiny HTTP server, so `ping`, `nc` and `curl` on your machine talk to code that doesn't use the kernel's networking for anything. Zero dependencies.

The sentence that sums up the project: Linux's `curl` downloaded a page from a "server" that was a `Vec<u8>` being assembled by hand, byte by byte, by my code. After that TCP stopped being magic.

```sh
cargo build --release
sudo ./target/release/rustnet            # creates tun0: host 10.0.0.1, stack 10.0.0.2

ping 10.0.0.2
echo hi | nc -u -w1 10.0.0.2 7
nc 10.0.0.2 7
curl http://10.0.0.2/
```

## Layers

- **TUN** (`src/tun.rs`): opens `/dev/net/tun` and configures it with the `TUNSETIFF` ioctl (declared by hand, no libc crate). Every IP packet the host sends to 10.0.0.2 arrives as bytes on that descriptor; what we write back the host receives as if it had come from the network.
- **Packets** (`src/packet.rs`): parsers and builders for IPv4, ICMP, UDP and TCP with the one's complement checksum, including the TCP/UDP pseudo-header. Bad checksum, fragments and truncated packets are rejected.
- **Stack** (`src/stack.rs`): demultiplexes by protocol and port. ICMP echo replies; UDP on port 7 echoes and on the others returns ICMP port unreachable; a SYN on a port with a service creates a connection, the rest gets an RST.
- **TCP** (`src/tcp.rs`): every connection is a state machine (LISTEN, SYN-RECEIVED, ESTABLISHED, CLOSE-WAIT, LAST-ACK, FIN-WAIT-1/2, CLOSING, TIME-WAIT). Data is only accepted in order (`seq == rcv.nxt`); the rest is re-ACKed. The application's replies are segmented by the MSS and the peer's window, sit in an unacknowledged queue and are retransmitted every second until the ACK arrives (giving up after six tries). The FIN goes out when the queue empties, and the other side's FIN goes through CLOSE-WAIT/LAST-ACK or FIN-WAIT/TIME-WAIT depending on who closed first.
- **Services**: `Echo` returns what it gets; `Http` gathers the request up to the blank line, replies with a page and closes.

## Tests

`cargo test` runs the unit tests: checksums (the RFC 1071 example), every packet codec, the TCP state machine (handshake, echo, out-of-order data, retransmission and giving up, both ways of closing, segmentation by MSS and window, RST) and the stack's demux.

`sudo cargo test -- --include-ignored` runs the end-to-end test: brings the stack up on a TUN and, with the real kernel on the other side, checks `ping`, UDP echo through a `UdpSocket`, a 5000-byte TCP echo through a `TcpStream` and `curl` fetching the page. CI runs this as root.

MIT.

# rustnet

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

**EN:** a userspace TCP/IP stack in dependency-free Rust on a Linux TUN device: IPv4/ICMP/UDP/TCP parsing with proper checksums, a TCP state machine with in-order delivery, MSS/window segmentation, retransmission and both teardown paths, and echo/HTTP services. The end-to-end test uses the real kernel as the peer (`ping`, UDP, a 5000-byte TCP echo and `curl`). MIT.

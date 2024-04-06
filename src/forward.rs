use by_address::ByAddress;

use either::Either;
use smol::net::{TcpListener, TcpStream};
use smol::{net::UdpSocket, prelude::*};
use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{nat::NatTable, run_command, Protocol};

/// A RAII struct that represents a port forwarder
pub struct Forwarder {
    protocol: Protocol,
    local_socket: Either<UdpSocket, TcpListener>,
    remote_addr: SocketAddr,
    iptables: bool,
    _task: smol::Task<()>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if self.iptables {
            let (protocol, local_port) = match self.protocol {
                Protocol::Tcp => (
                    "tcp",
                    self.local_socket
                        .as_ref()
                        .right()
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port(),
                ),
                Protocol::Udp => (
                    "udp",
                    self.local_socket
                        .as_ref()
                        .left()
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port(),
                ),
            };

            if protocol == "udp" {
                run_command(&format!(
                "iptables -t nat -D PREROUTING -p {} --dport {} -j DNAT --to-destination {}:{}; ",
                protocol,
                local_port,
                self.remote_addr.ip(),
                self.remote_addr.port(),
            ));
            }
        }
    }
}

impl Forwarder {
    /// Creates a new forwarder.
    pub fn new(
        protocol: Protocol,
        local_socket: Either<UdpSocket, TcpListener>,
        remote_addr: SocketAddr,
        iptables: bool,
    ) -> Self {
        if iptables {
            let (protocol, local_port) = match protocol {
                Protocol::Tcp => (
                    "tcp",
                    local_socket
                        .as_ref()
                        .right()
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port(),
                ),
                Protocol::Udp => (
                    "udp",
                    local_socket
                        .as_ref()
                        .left()
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port(),
                ),
            };

            if protocol == "udp" {
                run_command(&format!(
                "iptables -t nat -A PREROUTING -p {} --dport {} -j DNAT --to-destination {}:{}; ",
                protocol,
                local_port,
                remote_addr.ip(),
                remote_addr.port(),
            ));
            }
        }

        let task = match protocol {
            Protocol::Tcp => smolscale::spawn(tcp_forward(
                local_socket.as_ref().right().unwrap().clone(),
                remote_addr,
            )),
            Protocol::Udp => smolscale::spawn(udp_forward(
                local_socket.as_ref().left().unwrap().clone(),
                remote_addr,
            )),
        };

        Self {
            protocol,
            local_socket,
            remote_addr,
            iptables,
            _task: task,
        }
    }
}

async fn tcp_forward(local_tcp: TcpListener, remote_addr: SocketAddr) {
    loop {
        let (client, _) = local_tcp.accept().await.expect("tcp accept failed");
        smolscale::spawn(async move {
            let remote = TcpStream::connect(remote_addr).await;
            client.set_nodelay(true)?;

            match remote {
                Err(err) => {
                    log::warn!("failed to open connection to {}: {:?}", remote_addr, err);
                }
                Ok(remote) => {
                    remote.set_nodelay(true)?;
                    // PEEK at the client
                    log::debug!("PLAIN {} <=> {}", client.peer_addr()?, remote.peer_addr()?);
                    // two-way copy
                    let upload =
                        geph4_aioutils::copy_with_stats(client.clone(), remote.clone(), |_| ());
                    let download = copy_fragmented(remote, client);
                    let _ = upload.race(download).await;
                }
            }
            anyhow::Ok(())
        })
        .detach();
    }
}

async fn copy_fragmented(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> std::io::Result<()> {
    let mut buffer_size = 10usize;
    loop {
        let mut buff = vec![0u8; buffer_size];
        let n = reader.read(&mut buff).await?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buff[..n]).await?;
        writer.flush().await?;
        if buffer_size < 2000 {
            smol::Timer::after(Duration::from_millis(10)).await;
        }
        buffer_size = (buffer_size + 1).min(65536);
    }
}

struct CompositeReadWrite<R, W> {
    reader: R,
    writer: W,
}

impl<R: AsyncRead, W> AsyncRead for CompositeReadWrite<R, W> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.reader) };
        pinned.poll_read(cx, buf)
    }
}

impl<R, W: AsyncWrite> AsyncWrite for CompositeReadWrite<R, W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.writer) };
        pinned.poll_write(cx, buf)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.writer) };
        pinned.poll_close(cx)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.writer) };
        pinned.poll_flush(cx)
    }
}

// the tricky part: UDP natting
async fn udp_forward(local_udp: UdpSocket, remote_addr: SocketAddr) {
    let mut nat_table: NatTable<ByAddress<Arc<NatEntry>>> = NatTable::new(10000);
    let mut buf = [0u8; 2048];
    loop {
        let (n, client_addr) = local_udp
            .recv_from(&mut buf)
            .await
            .expect("cannot read from local_udp");
        let buf = &buf[..n];
        let entry = nat_table.addr_to_item(client_addr, || {
            // bind everything now
            let newly_bound = std::iter::from_fn(|| Some(fastrand::u32(1000..65536)))
                .take(10000)
                .find_map(|port| {
                    smol::future::block_on(UdpSocket::bind(
                        format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap(),
                    ))
                    .ok()
                })
                .expect("could not find a free port after 10000 tries");
            smol::future::block_on(newly_bound.connect(remote_addr)).expect("cannot 'connect' UDP");
            ByAddress(Arc::new(NatEntry {
                socket: newly_bound.clone(),
                _task: smolscale::spawn(udp_forward_downstream(
                    client_addr,
                    local_udp.clone(),
                    newly_bound,
                )),
            }))
        });
        if let Err(err) = entry.socket.send(buf).await {
            log::error!("cannot send through entry {:?}", err)
        }
    }
}

// one task
async fn udp_forward_downstream(
    client_addr: SocketAddr,
    local_udp: UdpSocket,
    remote_udp: UdpSocket,
) {
    let mut buf = [0u8; 2048];
    loop {
        match remote_udp.recv(&mut buf).await {
            Err(err) => {
                log::error!("error in downstream {:?}", err)
            }
            Ok(n) => {
                local_udp.send_to(&buf[..n], client_addr).await.unwrap();
            }
        }
    }
}

struct NatEntry {
    socket: UdpSocket,
    _task: smol::Task<()>,
}

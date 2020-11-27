use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use clap::{App, Arg};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use log::LevelFilter;
use smol::{
    channel::bounded,
    channel::Receiver,
    channel::Sender,
    future::FutureExt,
    net::{TcpListener, TcpStream, UdpSocket},
    Task,
};

mod async_kcp;
mod core;
mod crypto;
mod error;
mod segment;

use crate::{async_kcp::KcpHandle, core::KcpConfig, error::KcpResult};

#[async_trait::async_trait]
impl core::KcpIo for smol::net::UdpSocket {
    async fn send_packet(&self, buf: &[u8]) -> std::io::Result<()> {
        self.send(buf).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.recv(buf).await?;
        Ok(size)
    }
}

struct UdpListener {
    accept_rx: Receiver<UdpSession>,
    _task: Task<KcpResult<()>>,
}

impl UdpListener {
    async fn accept(&self) -> UdpSession {
        self.accept_rx.recv().await.unwrap()
    }

    fn new(udp: UdpSocket) -> Self {
        let udp = Arc::new(udp);
        let (accept_tx, accept_rx) = bounded(0x10);
        let _task = {
            let mut sessions = HashMap::<String, Sender<Bytes>>::new();
            let udp = udp.clone();
            smol::spawn(async move {
                loop {
                    let mut buf = Vec::new();
                    buf.resize(0x1000, 0u8);
                    let (size, addr) = udp.recv_from(&mut buf).await?;
                    let payload = Bytes::copy_from_slice(&buf[..size]);
                    if let Some(tx) = sessions.get(&addr.to_string()) {
                        tx.send(payload).await.unwrap();
                    } else {
                        let (tx, rx) = bounded(0x100);
                        sessions.insert(addr.to_string(), tx.clone());
                        let session = UdpSession {
                            udp: udp.clone(),
                            rx,
                            remote: addr,
                        };
                        accept_tx.send(session).await.unwrap();
                        tx.send(payload).await.unwrap();
                    }
                    sessions.retain(|_, tx| !tx.is_closed());
                }
            })
        };
        Self { _task, accept_rx }
    }
}

struct UdpSession {
    remote: SocketAddr,
    rx: Receiver<Bytes>,
    udp: Arc<UdpSocket>,
}

#[async_trait::async_trait]
impl core::KcpIo for UdpSession {
    async fn send_packet(&self, buf: &[u8]) -> std::io::Result<()> {
        self.udp.send_to(buf, self.remote).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let payload = self
                .rx
                .recv()
                .await
                .map_err(|_| std::io::ErrorKind::ConnectionReset)?;
            if payload.len() > buf.len() {
                log::error!("long packet");
                continue;
            }
            let len = payload.len();
            buf[..len].copy_from_slice(&payload);
            return Ok(len);
        }
    }
}

async fn relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    buf.resize(0x1000, 0u8);
    loop {
        let len = reader.read(&mut buf).await?;
        if len == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..len]).await?;
    }
}

async fn client(listener: TcpListener, kcp: KcpHandle<UdpSocket>) -> std::io::Result<()> {
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        log::info!("tcp accepted");
        let kcp_stream = kcp.connect().await?;
        log::info!("kcp connected");
        let t: Task<KcpResult<()>> = smol::spawn(async move {
            let mut tcp_reader = tcp_stream;
            let mut tcp_writer = tcp_reader.clone();
            let (mut kcp_reader, mut kcp_writer) = kcp_stream.split();
            let t1 = relay(&mut tcp_reader, &mut kcp_writer);
            let t2 = relay(&mut kcp_reader, &mut tcp_writer);
            let _ = t1.race(t2).await;
            let mut kcp_stream = kcp_reader.reunite(kcp_writer).unwrap();
            kcp_stream.close().await?;
            tcp_writer.close().await?;
            log::info!("client relay ends");
            Ok(())
        });
        t.detach();
    }
}

async fn server(addr: String, udp: UdpSocket) -> std::io::Result<()> {
    let listener = UdpListener::new(udp);
    let mut sessions: Vec<(Arc<KcpHandle<UdpSession>>, Task<KcpResult<()>>)> = Vec::new();
    loop {
        let udp_session = listener.accept().await;
        log::trace!("udp session accepted");
        let kcp = Arc::new(KcpHandle::new(udp_session, KcpConfig::default()));
        let t: Task<KcpResult<()>> = {
            let addr = addr.clone();
            let kcp = kcp.clone();
            smol::spawn(async move {
                let mut relay_task = Vec::new();
                loop {
                    let kcp_stream = kcp.accept().await?;
                    log::info!("kcp accepted");
                    let tcp_stream = TcpStream::connect(addr.clone()).await?;
                    log::info!("tcp connected");
                    let t: Task<KcpResult<()>> = smol::spawn(async move {
                        let mut tcp_reader = tcp_stream;
                        let mut tcp_writer = tcp_reader.clone();
                        let (mut kcp_reader, mut kcp_writer) = kcp_stream.split();
                        let t1 = relay(&mut tcp_reader, &mut kcp_writer);
                        let t2 = relay(&mut kcp_reader, &mut tcp_writer);
                        let _ = t1.race(t2).await;
                        let mut kcp_stream = kcp_reader.reunite(kcp_writer).unwrap();
                        kcp_stream.close().await?;
                        tcp_writer.close().await?;
                        log::info!("server relay ends");
                        Ok(())
                    });
                    relay_task.push(t);
                }
            })
        };
        sessions.retain(|(handle, _)| {
            let ok = smol::block_on(async {
                let count = handle.get_stream_count().await;
                log::info!("{}", count);
                count > 0
            });
            if !ok {
                log::info!("remove kcp handle");
            }
            ok
        });
        sessions.push((kcp, t));
    }
}

fn main() {
    std::env::set_var("SMOL_THREADS", "8");
    let _ = env_logger::builder()
        .filter_module("ap_kcp", LevelFilter::Info)
        .try_init();
    let matches = App::new("ap_kcp")
        .arg(
            Arg::with_name("local")
                .long("local")
                .short("l")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("remote")
                .long("remote")
                .short("r")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("client")
                .long("client")
                .short("c")
                .conflicts_with("server"),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .short("s")
                .conflicts_with("client"),
        )
        .get_matches();
    smol::block_on(async move {
        let local = matches.value_of("local").unwrap();
        let remote = matches.value_of("remote").unwrap();
        if matches.is_present("client") {
            let udp = UdpSocket::bind(":::0").await.unwrap();
            udp.connect(remote).await.unwrap();
            let kcp_handle = KcpHandle::new(udp, KcpConfig::default());
            let listener = TcpListener::bind(local).await.unwrap();
            client(listener, kcp_handle).await.unwrap();
        } else if matches.is_present("server") {
            let udp = UdpSocket::bind(local).await.unwrap();
            server(remote.to_string(), udp).await.unwrap();
        }
    })
}

#[test]
fn simple_iperf() {
    std::env::set_var("SMOL_THREADS", "8");
    let _ = env_logger::builder()
        .filter_module("ap_kcp", LevelFilter::Info)
        .try_init();
    let t1 = smol::spawn(async move {
        let local = "127.0.0.1:5000";
        let remote = "127.0.0.1:6000";
        let udp = UdpSocket::bind(":::0").await.unwrap();
        udp.connect(remote).await.unwrap();
        let kcp_handle = KcpHandle::new(udp, KcpConfig::default());
        let listener = TcpListener::bind(local).await.unwrap();
        client(listener, kcp_handle).await.unwrap();
    });

    let t2 = smol::spawn(async move {
        let local = "127.0.0.1:6000";
        let remote = "127.0.0.1:5201";
        let udp = UdpSocket::bind(local).await.unwrap();
        server(remote.to_string(), udp).await.unwrap();
    });
    smol::block_on(async {
        t1.race(t2).await;
    });
}

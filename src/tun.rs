use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use clap::{App, Arg};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use log::LevelFilter;
use ring::aead;
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
mod udp;

use crate::{
    async_kcp::KcpHandle,
    core::{KcpConfig, KcpIo},
    crypto::{AeadCrypto, Crypto, CryptoLayer},
    error::KcpResult,
};

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
                let mut buf = Vec::new();
                buf.resize(0x1000, 0u8);
                loop {
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
                        sessions.retain(|_, tx| !tx.is_closed());
                    }
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

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.rx.close();
    }
}

#[async_trait::async_trait]
impl core::KcpIo for UdpSession {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.udp.send_to(buf, self.remote).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
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
            buf.resize(len, 0);
            buf.copy_from_slice(&payload);
            return Ok(());
        }
    }
}

async fn relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    buf.resize(0x2000, 0u8);
    loop {
        let len = reader.read(&mut buf).await?;
        if len == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..len]).await?;
    }
}

async fn client<C: Crypto + 'static>(
    local: String,
    crypto: C,
    udp: UdpSocket,
    config: KcpConfig,
) -> std::io::Result<()> {
    let udp = CryptoLayer::wrap(udp, crypto);
    let kcp_handle = KcpHandle::new(udp, config)?;
    let listener = TcpListener::bind(local).await?;
    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        log::info!("tcp socket accepted: {}", addr);
        let kcp_stream = kcp_handle.connect().await?;
        log::info!("kcp tunnel established");
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
            log::info!("client-side tunnel closed");
            Ok(())
        });
        t.detach();
    }
}

async fn server<C: Crypto + 'static>(
    addr: String,
    udp: UdpSocket,
    crypto: C,
    config: KcpConfig,
) -> std::io::Result<()> {
    config.check()?;
    let listener = UdpListener::new(udp);
    let crypto = Arc::new(crypto);
    let mut sessions: Vec<(
        Arc<KcpHandle<CryptoLayer<UdpSession, Arc<C>>>>,
        Task<KcpResult<()>>,
    )> = Vec::new();

    loop {
        let udp_session = listener.accept().await;
        log::trace!("udp session accepted: {}", udp_session.remote);
        let udp_session = CryptoLayer::wrap(udp_session, crypto.clone());
        let kcp = Arc::new(KcpHandle::new(udp_session, config.clone()).unwrap());
        let t: Task<KcpResult<()>> = {
            let addr = addr.clone();
            let kcp = kcp.clone();
            smol::spawn(async move {
                let mut relay_task = Vec::new();
                loop {
                    let kcp_stream = kcp.accept().await?;
                    log::info!("kcp tunnel established");
                    let tcp_stream = TcpStream::connect(addr.clone()).await?;
                    log::info!("tunneling to {}", addr);
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
                        log::info!("server-side tunnel closed");
                        Ok(())
                    });
                    relay_task.push(t);
                }
            })
        };
        sessions.retain(|(handle, _)| {
            let ok = smol::block_on(async {
                let count = handle.get_stream_count().await;
                log::debug!("count = {}", count);
                count > 0
            });
            if !ok {
                log::info!("removing kcp handle");
            }
            ok
        });
        sessions.push((kcp, t));
    }
}

fn get_algorithm(name: &str) -> &'static aead::Algorithm {
    match name {
        "aes-128-gcm" => &aead::AES_128_GCM,
        "aes-256-gcm" => &aead::AES_256_GCM,
        "chacha20-poly1305" => &aead::CHACHA20_POLY1305,
        _ => {
            panic!("no algorithm named {}", name)
        }
    }
}

fn main() {
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
        .arg(
            Arg::with_name("password")
                .long("password")
                .short("p")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("algorithm")
                .long("algorithm")
                .short("a")
                .takes_value(true)
                .required(true)
                .validator(|name| match name.as_str() {
                    "aes-256-gcm" => Ok(()),
                    "aes-128-gcm" => Ok(()),
                    "chacha20-poly1305" => Ok(()),
                    _ => Err(
                        "Valid crypto algorithm: aes-256-gcm, aes-128-gcm, chacha20-poly1305"
                            .to_string(),
                    ),
                })
                .default_value("aes-256-gcm"),
        )
        .arg(
            Arg::with_name("kcp-config")
                .long("kcp-config")
                .short("k")
                .takes_value(true)
                .required(false),
        )
        .author("black-binary")
        .version("0.1.0")
        .get_matches();

    let thread = num_cpus::get() + 2;
    std::env::set_var("SMOL_THREADS", thread.to_string());

    let _ = env_logger::builder()
        .filter_module("ap_kcp", LevelFilter::Info)
        .try_init();

    let config = match matches.value_of("kcp-config") {
        Some(path) => {
            let content = fs::read_to_string(path).unwrap();
            let config = toml::from_str::<KcpConfig>(&content).unwrap();
            config
        }
        None => KcpConfig::default(),
    };

    smol::block_on(async move {
        let local = matches.value_of("local").unwrap();
        let remote = matches.value_of("remote").unwrap();
        let password = matches.value_of("password").unwrap();
        let algorithm_name = matches.value_of("algorithm").unwrap();
        let aead = AeadCrypto::new(password.as_bytes(), get_algorithm(algorithm_name));

        if matches.is_present("client") {
            log::info!("ap-kcp client");
            log::info!("listening on {}, tunneling via {}", local, remote);
            log::info!("algorithm: {}", algorithm_name);
            log::info!("settings: {:?}", config);
            let udp = UdpSocket::bind(":::0").await.unwrap();
            udp.connect(remote).await.unwrap();
            client(local.to_string(), aead, udp, config).await.unwrap();
        } else if matches.is_present("server") {
            log::info!("ap-kcp server");
            log::info!("listening on {}, tunneling to {}", local, remote);
            log::info!("algorithm: {}", algorithm_name);
            log::info!("settings: {:?}", config);
            let udp = UdpSocket::bind(local).await.unwrap();
            server(remote.to_string(), udp, aead, config).await.unwrap();
        } else {
            log::warn!("neither --server or --client is specified")
        }
    })
}

#[test]
fn simple_iperf() {
    std::env::set_var("SMOL_THREADS", "8");
    let _ = env_logger::builder()
        .filter_module("ap_kcp", LevelFilter::Info)
        .try_init();
    let password = "password";
    let t1 = smol::spawn(async move {
        let local = "127.0.0.1:5000";
        let remote = "127.0.0.1:6000";
        let udp = UdpSocket::bind(":::0").await.unwrap();
        udp.connect(remote).await.unwrap();
        let aead = AeadCrypto::new(password.as_bytes(), &aead::AES_256_GCM);
        let config = KcpConfig::default();
        client(local.to_string(), aead, udp, config).await.unwrap();
    });

    let t2 = smol::spawn(async move {
        let local = "127.0.0.1:6000";
        let remote = "127.0.0.1:5201";
        let udp = UdpSocket::bind(local).await.unwrap();
        let aead = AeadCrypto::new(password.as_bytes(), &aead::AES_256_GCM);
        let config = KcpConfig::default();
        server(remote.to_string(), udp, aead, config).await.unwrap();
    });
    smol::block_on(async {
        t1.race(t2).await;
    });
}

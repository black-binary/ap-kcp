use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use smol::{
    channel::{bounded, Receiver, Sender},
    net::UdpSocket,
    Task,
};

use crate::{error::KcpResult, KcpIo};

const UDP_MTU: usize = 0x1000;

#[async_trait::async_trait]
impl KcpIo for smol::net::UdpSocket {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.send(buf).await?;
        Ok(())
    }

    async fn recv_packet(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(UDP_MTU);
        unsafe {
            buf.set_len(UDP_MTU);
        }
        let size = self.recv(&mut buf).await?;
        buf.truncate(size);
        Ok(buf)
    }
}

pub struct UdpListener {
    accept_rx: Receiver<UdpSession>,
    _task: Task<KcpResult<()>>,
}

impl UdpListener {
    pub async fn accept(&self) -> UdpSession {
        self.accept_rx.recv().await.unwrap()
    }

    pub fn new(udp: UdpSocket) -> Self {
        let udp = Arc::new(udp);
        let (accept_tx, accept_rx) = bounded(0x10);
        let _task = {
            let mut sessions = HashMap::<String, Sender<Vec<u8>>>::new();
            smol::spawn(async move {
                loop {
                    let mut buf = Vec::with_capacity(UDP_MTU);
                    unsafe {
                        buf.set_len(UDP_MTU);
                    }
                    let (size, addr) = udp.recv_from(&mut buf).await?;
                    buf.truncate(size);
                    let mut should_clean = false;
                    if let Some(tx) = sessions.get(&addr.to_string()) {
                        if tx.is_closed() {
                            should_clean = true;
                        } else if tx.try_send(buf).is_err() {
                            log::debug!("the channel got jammed!");
                        }
                    } else {
                        let (tx, rx) = bounded(0x200);
                        sessions.insert(addr.to_string(), tx.clone());
                        let session = UdpSession {
                            udp: udp.clone(),
                            rx,
                            remote: addr,
                        };
                        accept_tx.send(session).await.unwrap();
                        tx.send(buf).await.unwrap();
                        should_clean = true;
                    }
                    if should_clean {
                        log::info!("cleaning dead session...");
                        sessions.retain(|_, tx| !tx.is_closed());
                    }
                }
            })
        };
        Self { _task, accept_rx }
    }
}

pub struct UdpSession {
    remote: SocketAddr,
    rx: Receiver<Vec<u8>>,
    udp: Arc<UdpSocket>,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.rx.close();
    }
}

impl UdpSession {
    #[inline]
    pub fn get_remote(&self) -> &SocketAddr {
        &self.remote
    }
}

#[async_trait::async_trait]
impl KcpIo for UdpSession {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.udp.send_to(buf, self.remote).await?;
        Ok(())
    }

    async fn recv_packet(&self) -> std::io::Result<Vec<u8>> {
        let packet = self
            .rx
            .recv()
            .await
            .map_err(|_| std::io::ErrorKind::ConnectionReset)?;
        return Ok(packet);
    }
}

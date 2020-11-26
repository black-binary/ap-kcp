use std::{
    collections::HashMap,
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes};
use futures::{ready, AsyncRead, AsyncWrite, Future};
use futures_timer::Delay;
use smol::{
    channel::{bounded, Receiver, Sender},
    future::FutureExt,
    lock::{Mutex, MutexGuardArc},
    Task,
};

use crate::{
    core::{KcpConfig, KcpCore, KcpIo},
    error::{KcpError, KcpResult},
    segment::{KcpSegment, CMD_PING, CMD_PUSH, HEADER_SIZE},
};

type LockCoreFuture = Pin<Box<dyn Future<Output = MutexGuardArc<KcpCore>> + Send>>;

pub struct KcpStream {
    core: Arc<Mutex<KcpCore>>,
    read_buffer: Option<VecDeque<Bytes>>,
    recv_lock_future: Option<LockCoreFuture>,
    send_lock_future: Option<LockCoreFuture>,
    flush_lock_future: Option<LockCoreFuture>,
    close_lock_future: Option<LockCoreFuture>,
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        smol::block_on(async {
            let _ = self.core.lock().await.try_close();
        });
        log::trace!("kcp stream dropped");
    }
}

impl KcpStream {
    #[inline]
    fn lock_core(
        cx: &mut Context<'_>,
        core: Arc<Mutex<KcpCore>>,
        future_storage: &mut Option<Pin<Box<dyn Future<Output = MutexGuardArc<KcpCore>> + Send>>>,
    ) -> Poll<MutexGuardArc<KcpCore>> {
        if future_storage.is_none() {
            if let Some(core) = core.try_lock_arc() {
                return Poll::Ready(core);
            }
            let fut = {
                let core = core.clone();
                async move { core.lock_arc().await }
            }
            .boxed();
            *future_storage = Some(fut);
        }
        let core = ready!(future_storage.as_mut().unwrap().poll(cx));
        *future_storage = None;
        Poll::Ready(core)
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            if self.read_buffer.is_some() {
                if self.read_buffer.as_mut().unwrap().is_empty() {
                    self.read_buffer = None;
                } else {
                    let queue = self.read_buffer.as_mut().unwrap();
                    let payload = queue.front_mut().unwrap();
                    if payload.remaining() > buf.len() {
                        let buf_len = buf.len();
                        buf.copy_from_slice(&payload[..buf_len]);
                        payload.advance(buf_len);
                        return Poll::Ready(Ok(buf_len));
                    }
                    let len = payload.remaining();
                    payload.copy_to_slice(&mut buf[..len]);
                    queue.pop_front();
                    return Poll::Ready(Ok(len));
                }
            }
            let mut core = ready!(Self::lock_core(
                cx,
                self.core.clone(),
                &mut self.recv_lock_future
            ));
            let payload = ready!(core.poll_recv(cx))?;
            self.read_buffer = Some(payload);
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.len() == 0 {
            // Never send an empty packet
            return Poll::Ready(Ok(0));
        }
        let mut core = ready!(Self::lock_core(
            cx,
            self.core.clone(),
            &mut self.send_lock_future,
        ));
        ready!(core.poll_send(cx, buf))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut core = ready!(Self::lock_core(
            cx,
            self.core.clone(),
            &mut self.flush_lock_future,
        ));
        ready!(core.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut core = ready!(Self::lock_core(
            cx,
            self.core.clone(),
            &mut self.close_lock_future,
        ));
        ready!(core.poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

struct KcpSession {
    core: Arc<Mutex<KcpCore>>,
    _update_task: Task<KcpResult<()>>,
}

pub struct KcpHandle<T> {
    sessions: Arc<Mutex<HashMap<u16, KcpSession>>>,
    config: Arc<KcpConfig>,
    accept_rx: Receiver<KcpStream>,
    dead_tx: Sender<u16>,
    io: Arc<T>,
    _feed_packet_task: Task<KcpResult<()>>,
    _clean_task: Task<KcpResult<()>>,
}

impl<T> Drop for KcpHandle<T> {
    fn drop(&mut self) {
        smol::block_on(async move {
            self.accept_rx.close();
            let sessions = self.sessions.lock().await;
            for (_, session) in sessions.iter() {
                let _ = session.core.lock().await.force_close();
            }
        });
        log::trace!("kcp handle dropped");
    }
}

impl<IO: KcpIo + Send + Sync + 'static> KcpHandle<IO> {
    pub async fn get_stream_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    async fn find_new_stream_id(&self) -> KcpResult<u16> {
        let sessions = self.sessions.lock().await;
        if sessions.len() == 0xffff {
            return Err(KcpError::TooManyStreams);
        }
        let stream_id = rand::random();
        if !sessions.contains_key(&stream_id) {
            return Ok(stream_id);
        }
        for i in 0..0xffffu16 {
            if !sessions.contains_key(&i) {
                return Ok(i);
            }
        }
        Err(KcpError::TooManyStreams)
    }

    pub async fn connect(&self) -> KcpResult<KcpStream> {
        let stream_id = self.find_new_stream_id().await?;
        let (tx, rx) = bounded(1);
        let core = Arc::new(Mutex::new(KcpCore::new(stream_id, self.config.clone(), tx)));
        let stream = KcpStream {
            core: core.clone(),
            read_buffer: None,
            recv_lock_future: None,
            send_lock_future: None,
            flush_lock_future: None,
            close_lock_future: None,
        };
        let _update_task = smol::spawn(Self::update(
            core.clone(),
            self.io.clone(),
            rx,
            self.dead_tx.clone(),
        ));
        self.sessions
            .lock()
            .await
            .insert(stream_id, KcpSession { core, _update_task });
        Ok(stream)
    }

    pub async fn accept(&self) -> KcpResult<KcpStream> {
        match self.accept_rx.recv().await {
            Ok(stream) => {
                return Ok(stream);
            }
            Err(_) => {
                return Err(KcpError::Shutdown(
                    "accpeting but kcp handle is closed".to_string(),
                ));
            }
        }
    }

    async fn clean(
        sessions: Arc<Mutex<HashMap<u16, KcpSession>>>,
        dead_rx: Receiver<u16>,
    ) -> KcpResult<()> {
        loop {
            let stream_id = dead_rx
                .recv()
                .await
                .map_err(|_| KcpError::Shutdown("cleaning but kcp handle is closed".to_string()))?;
            sessions.lock().await.remove(&stream_id);
            log::trace!("cleaning {}", stream_id);
        }
    }

    async fn update(
        core: Arc<Mutex<KcpCore>>,
        io: Arc<IO>,
        flush_notify_rx: Receiver<()>,
        dead_tx: Sender<u16>,
    ) -> KcpResult<()> {
        loop {
            let interval = {
                let mut core = core.lock().await;
                if let Err(e) = core.flush(&*io).await {
                    log::error!("flush error: {}", e);
                    let _ = dead_tx.send(core.get_stream_id()).await;
                    return Err(KcpError::Shutdown(
                        "update task is shutting down".to_string(),
                    ));
                }
                core.get_interval()
            };
            let delay = Delay::new(Duration::from_millis(interval as u64));
            let notify = async {
                let _ = flush_notify_rx.recv().await;
                log::trace!("wake up now!");
            };
            let tick = async move {
                delay.await;
            };

            notify.race(tick).await;
        }
    }

    async fn feed_packet(
        sessions: Arc<Mutex<HashMap<u16, KcpSession>>>,
        config: Arc<KcpConfig>,
        io: Arc<IO>,
        accept_tx: Sender<KcpStream>,
        dead_tx: Sender<u16>,
    ) -> KcpResult<()> {
        let mut buf = Vec::new();
        buf.resize(config.mtu, 0);
        loop {
            let size = io.recv_packet(&mut buf).await?;
            if size < HEADER_SIZE {
                log::error!("short packet length {}", size);
                continue;
            }

            let stream_id = KcpSegment::peek_stream_id(&buf[..size]);
            let mut packet = &buf[..size];
            let mut segments = Vec::new();
            let mut is_invalid_packet = false;
            let mut new_stream = false;

            while packet.has_remaining() {
                match KcpSegment::decode(&packet) {
                    Ok(segment) => {
                        if segment.stream_id != stream_id {
                            is_invalid_packet = true;
                            log::error!("invalid packet format");
                            break;
                        }
                        // First push or ping
                        if (segment.command == CMD_PUSH || segment.command == CMD_PING)
                            && segment.sequence == 0
                        {
                            new_stream = true;
                        }
                        packet.advance(segment.encoded_len());
                        segments.push(segment);
                    }
                    Err(e) => {
                        log::error!("malformed packet: {}", e);
                        is_invalid_packet = true;
                        break;
                    }
                }
            }

            if is_invalid_packet {
                continue;
            }

            let mut is_new_stream = false;

            let core = {
                let mut sessions = sessions.lock().await;

                if let Some(session) = sessions.get_mut(&stream_id) {
                    session.core.clone()
                } else {
                    if new_stream {
                        let (tx, rx) = bounded(1);
                        let core =
                            Arc::new(Mutex::new(KcpCore::new(stream_id, config.clone(), tx)));
                        let update_task = {
                            let core = core.clone();
                            let io = io.clone();
                            smol::spawn(Self::update(core, io, rx, dead_tx.clone()))
                        };
                        sessions.insert(
                            stream_id,
                            KcpSession {
                                core: core.clone(),
                                _update_task: update_task,
                            },
                        );
                        is_new_stream = true;
                        log::trace!("new kcp stream");
                        core
                    } else {
                        log::error!("unknown stream_id {}", stream_id);
                        continue;
                    }
                }
            };

            if is_new_stream {
                let stream = KcpStream {
                    core: core.clone(),
                    read_buffer: None,
                    recv_lock_future: None,
                    send_lock_future: None,
                    flush_lock_future: None,
                    close_lock_future: None,
                };
                if accept_tx.send(stream).await.is_err() {
                    log::error!("kcp handle closed");
                    return Ok(());
                };
            }

            if core.lock().await.input(segments).is_err() {
                sessions.lock().await.remove(&stream_id);
                log::trace!("removing dead link")
            };
        }
    }

    pub fn new(io: IO, config: KcpConfig) -> Self {
        let io = Arc::new(io);
        let config = Arc::new(config);
        let sessions = Arc::new(Mutex::new(HashMap::<u16, KcpSession>::new()));

        let (accept_tx, accept_rx) = bounded(0x10);
        let (dead_tx, dead_rx) = bounded(0x10);

        // The only task reading the socket
        let _feed_packet_task = smol::spawn(Self::feed_packet(
            sessions.clone(),
            config.clone(),
            io.clone(),
            accept_tx,
            dead_tx.clone(),
        ));

        let _clean_task = smol::spawn(Self::clean(sessions.clone(), dead_rx.clone()));

        Self {
            sessions,
            config,
            accept_rx,
            io,
            _feed_packet_task,
            _clean_task,
            dead_tx,
        }
    }
}

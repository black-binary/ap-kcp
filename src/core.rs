use std::{
    cmp,
    collections::{HashMap, VecDeque},
    sync::Arc,
    task::{Context, Poll, Waker},
    time::SystemTime,
};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use smol::channel::Sender;

use crate::{
    error::{KcpError, KcpResult},
    segment::{KcpSegment, CMD_ACK, CMD_PING, CMD_PUSH, HEADER_SIZE},
};

pub const RTO_INIT: u32 = 200;
pub const SSTHRESH_MIN: u16 = 2;
pub const MIN_WINDOW_SIZE: u16 = 0x10;
pub const MAX_WINDOW_SIZE: u16 = 0x8000;

#[async_trait::async_trait]
pub trait KcpIo {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()>;
    async fn recv_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()>;
}

#[inline(always)]
fn now_millis() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32
}

#[inline(always)]
fn i32diff(a: u32, b: u32) -> i32 {
    a as i32 - b as i32
}

#[inline(always)]
fn bound<T: Ord>(lower: T, v: T, upper: T) -> T {
    cmp::min(cmp::max(lower, v), upper)
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Congestion {
    None,
    KcpReno,
    LossTolerance,
}

#[cfg(feature = "serde_support")]
impl<'de> serde::Deserialize<'de> for Congestion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "none" => Ok(Self::None),
            "reno" => Ok(Self::KcpReno),
            "loss_tolerance" => Ok(Self::LossTolerance),
            _ => Ok(Self::LossTolerance),
        }
    }
}

bitflags! {
    struct CloseFlags: u8 {
        const TX_CLOSING = 0b00000001;
        const TX_CLOSED = 0b00000011;
        const RX_CLOSED = 0b00000100;
        const CLOSED = Self::TX_CLOSED.bits | Self::RX_CLOSED.bits;
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde_support", derive(serde_derive::Deserialize))]
pub struct KcpConfig {
    pub max_interval: u32,
    pub min_interval: u32,
    pub nodelay: bool,
    pub mtu: usize,
    pub mss: usize,
    pub fast_rexmit_thresh: u32,
    pub fast_ack_thresh: u32,
    pub congestion: Congestion,
    pub max_rexmit_time: u32,
    pub min_rto: u32,
    pub send_window_size: u16,
    pub recv_window_size: u16,
    pub timeout: u32,
    pub keep_alive_interval: u32,
    pub name: String,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            min_interval: 10,
            max_interval: 100,
            nodelay: false,
            mtu: 1400 - 28,
            mss: 1400 - 28 - HEADER_SIZE,
            fast_rexmit_thresh: 3,
            fast_ack_thresh: 32,
            congestion: Congestion::LossTolerance,
            max_rexmit_time: 32,
            min_rto: 20,
            send_window_size: 0x1000,
            recv_window_size: 0x1000,
            timeout: 5000,
            keep_alive_interval: 1500,
            name: "".to_string(),
        }
    }
}

impl KcpConfig {
    pub fn check(&self) -> KcpResult<()> {
        if self.min_interval > self.max_interval {
            return Err(KcpError::InvalidConfig(
                "min_interval > max_interval".to_string(),
            ));
        }
        if self.min_interval < 10 || self.min_interval >= 1000 {
            return Err(KcpError::InvalidConfig(
                "min_interval should be in range (10, 1000)".to_string(),
            ));
        }
        if self.send_window_size < MIN_WINDOW_SIZE || self.send_window_size > MAX_WINDOW_SIZE {
            return Err(KcpError::InvalidConfig(format!(
                "send_window_size should be in range ({}, {})",
                MIN_WINDOW_SIZE, MAX_WINDOW_SIZE
            )));
        }
        if self.recv_window_size < MIN_WINDOW_SIZE || self.recv_window_size > MAX_WINDOW_SIZE {
            return Err(KcpError::InvalidConfig(format!(
                "recv_window_size should be in range ({}, {})",
                MIN_WINDOW_SIZE, MAX_WINDOW_SIZE
            )));
        }
        if self.mss > self.mtu - HEADER_SIZE {
            return Err(KcpError::InvalidConfig(
                "mss > mtu - HEADER_SIZE".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "serde_support")]
    #[test]
    fn deserialize() {
        use super::*;
        let s = r#"
    max_interval = 10
    min_interval = 100
    nodelay = false
    mtu = 1350
    mss = 1331
    fast_rexmit_thresh = 3
    fast_ack_thresh = 32
    congestion = "loss_tolerance"
    max_rexmit_time = 32
    min_rto = 20
    send_window_size = 0x800
    recv_window_size = 0x800
    timeout = 5000
    keep_alive_interval = 1500
    "#;
        let config = toml::from_str::<KcpConfig>(s).unwrap();
        assert_eq!(config.max_interval, 10);
        assert_eq!(config.min_interval, 100);
        assert_eq!(config.congestion, Congestion::LossTolerance);
    }
}

struct SendingKcpSegment {
    segment: KcpSegment,
    rexmit_timestamp: u32,
    rto: u32,
    fast_rexmit_counter: u32,
    rexmit_counter: u32,
}

pub(crate) struct KcpCore {
    stream_id: u16,
    send_queue: VecDeque<BytesMut>,
    send_window: VecDeque<SendingKcpSegment>,
    recv_queue: VecDeque<Bytes>,
    recv_window: HashMap<u32, KcpSegment>,
    ack_list: VecDeque<(u32, u32)>,

    send_unack: u32,
    send_next: u32,
    recv_next: u32,

    remote_window_size: u16,
    congestion_window_size: u16,
    congestion_window_bytes: usize,
    slow_start_thresh: u16,

    srtt: u32,
    rttval: u32,
    rto: u32,

    now: u32,
    ping_ts: u32,

    close_state: CloseFlags,
    close_moment: u32,

    buffer: Vec<u8>,

    pub config: Arc<KcpConfig>,

    send_waker: Option<Waker>,
    recv_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    close_waker: Option<Waker>,

    flush_notify_tx: Sender<()>,

    last_active: u32,

    push_counter: u32,
    rexmit_counter: u32,
    last_measure: u32,
}

impl Drop for KcpCore {
    fn drop(&mut self) {
        log::trace!("kcp core dropped");
        self.force_close();
    }
}

impl KcpCore {
    #[inline]
    pub fn get_stream_id(&self) -> u16 {
        self.stream_id
    }

    pub fn force_close(&mut self) {
        self.close_state.set(CloseFlags::CLOSED, true);
        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.close_waker.take() {
            waker.wake();
        }
    }

    fn remove_send_window_until(&mut self, sequence: u32) {
        while self.send_window.len() != 0 {
            if i32diff(sequence, self.send_window.front().unwrap().segment.sequence) > 0 {
                self.send_window.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_unack(&mut self) {
        self.send_unack = match self.send_window.front() {
            Some(sending_segment) => sending_segment.segment.sequence,
            None => self.send_next,
        }
    }

    fn update_rtt(&mut self, rtt: u32) {
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rttval = rtt / 2;
        } else {
            let delta = if rtt > self.srtt {
                rtt - self.srtt
            } else {
                self.srtt - rtt
            };
            self.rttval = (3 * self.rttval + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < 1 {
                self.srtt = 1;
            }
        }
        let rto = self.srtt + cmp::max(self.config.max_interval, 4 * self.rttval);
        self.rto = bound(self.config.min_rto, rto, self.config.timeout);
        log::trace!("update srtt = {}, rto = {}", self.srtt, rto);
    }

    fn remove_from_send_window(&mut self, sequence: u32) {
        // Make sure send_una <= seq < send_next
        if i32diff(sequence, self.send_unack) < 0 || i32diff(sequence, self.send_next) >= 0 {
            return;
        }

        for i in 0..self.send_window.len() {
            let segment_seq = self.send_window[i].segment.sequence;
            if sequence == segment_seq {
                self.send_window.remove(i);
                break;
            } else if sequence < segment_seq {
                break;
            }
        }
    }

    fn update_fast_rexmit(&mut self, sequence: u32) {
        if i32diff(sequence, self.send_unack) < 0 || i32diff(sequence, self.send_next) >= 0 {
            return;
        }

        for sending_segment in &mut self.send_window {
            let segment_seq = sending_segment.segment.sequence;
            if i32diff(sequence, segment_seq) < 0 {
                break;
            } else if segment_seq != sequence {
                sending_segment.fast_rexmit_counter += 1;
            }
        }
    }

    fn handle_ack(&mut self, segment: &KcpSegment) {
        let mut cursor = &segment.data[..];
        let mut max_ack = 0;
        let mut ack_num = 0;
        let old_send_unack = self.send_unack;

        while cursor.remaining() >= 8 {
            let timestamp = cursor.get_u32_le();
            let sequence = cursor.get_u32_le();

            if timestamp < self.now {
                self.update_rtt(self.now - timestamp);
            }
            self.remove_from_send_window(sequence);
            if sequence > max_ack {
                max_ack = sequence;
            }
            ack_num += 1;
        }

        self.update_unack();
        self.update_fast_rexmit(max_ack);

        if self.send_unack > old_send_unack {
            // Some packets were sent and acked successfully
            // It's time to update cwnd
            match self.config.congestion {
                Congestion::None => {}
                Congestion::KcpReno => {
                    for _ in 0..ack_num {
                        if self.congestion_window_size < self.remote_window_size {
                            let mss = self.config.mss;
                            if self.congestion_window_size < self.slow_start_thresh {
                                // Slow start
                                self.congestion_window_size += 1;
                                self.congestion_window_bytes += mss;
                            } else {
                                // Congestion control
                                self.congestion_window_bytes +=
                                    (mss * mss) / self.congestion_window_bytes + (mss / 16);
                                if (self.congestion_window_size + 1) as usize * mss
                                    <= self.congestion_window_bytes
                                {
                                    self.congestion_window_size += 1;
                                }
                            }

                            if self.congestion_window_size > self.remote_window_size {
                                self.congestion_window_size = self.remote_window_size;
                                self.congestion_window_bytes =
                                    self.remote_window_size as usize * mss;
                            }
                        } else {
                            break;
                        }
                    }
                }
                Congestion::LossTolerance => {}
            }
            log::trace!(
                "ack, cwnd = {}, incr = {}",
                self.congestion_window_size,
                self.congestion_window_bytes
            );
        }
        log::trace!("input ack");
    }

    fn handle_push(&mut self, segment: &KcpSegment) {
        if i32diff(
            segment.sequence,
            self.recv_next + self.config.recv_window_size as u32,
        ) < 0
        {
            self.ack_list
                .push_back((segment.timestamp, segment.sequence));
            if self.ack_list.len() >= self.config.fast_ack_thresh as usize {
                let _ = self.flush_notify_tx.try_send(());
            }
            if i32diff(segment.sequence, self.recv_next) >= 0 {
                if !self.recv_window.contains_key(&segment.sequence) {
                    self.recv_window.insert(segment.sequence, segment.clone());
                }
                while self.recv_window.contains_key(&self.recv_next) {
                    let segment = self.recv_window.remove(&self.recv_next).unwrap();
                    // Empty payload, closing
                    log::trace!("empty payload, closing");
                    if segment.data.len() == 0 {
                        // No more data from the peer
                        // This is the last segment moved into send_queue
                        self.close_state.set(CloseFlags::RX_CLOSED, true);
                        // Try to close local tx
                        if !self.close_state.contains(CloseFlags::TX_CLOSING) {
                            self.close_state.set(CloseFlags::TX_CLOSING, true);
                            self.send_queue.push_back(BytesMut::new());
                        }
                        break;
                    }
                    self.recv_queue.push_back(segment.data);
                    self.recv_next += 1;
                }
            }
        }

        log::trace!("input push");
    }

    pub fn input(&mut self, segments: Vec<KcpSegment>) -> KcpResult<()> {
        self.now = now_millis();
        self.last_active = self.now;

        for segment in &segments {
            assert_eq!(segment.stream_id, self.stream_id);
            log::trace!("input segment: {:?}", segment);
            self.remote_window_size = segment.recv_window_size;
            self.remove_send_window_until(segment.recv_next);
            self.update_unack();

            match segment.command {
                CMD_ACK => {
                    self.handle_ack(segment);
                }
                CMD_PUSH => {
                    self.handle_push(segment);
                }
                CMD_PING => {
                    log::trace!("input ping");
                }
                _ => unreachable!(),
            }
        }

        if self.close_state.contains(CloseFlags::TX_CLOSING)
            && self.send_window.is_empty()
            && self.send_queue.is_empty()
        {
            // The last empty packet was sent and acked by the peer
            log::trace!("TX_CLOSING to TX_CLOSED");
            self.close_state.set(CloseFlags::TX_CLOSED, true);
        }

        self.try_wake_stream();
        Ok(())
    }

    #[inline]
    fn try_wake_stream(&mut self) {
        if self.send_ready() && self.send_waker.is_some() {
            let waker = self.send_waker.take().unwrap();
            log::trace!("waking send task");
            waker.wake();
        }

        if self.recv_ready() && self.recv_waker.is_some() {
            let waker = self.recv_waker.take().unwrap();
            log::trace!("waking recv task");
            waker.wake();
        }

        if self.flush_ready() && self.flush_waker.is_some() {
            let waker = self.flush_waker.take().unwrap();
            log::trace!("waking flush task");
            waker.wake();
        }
    }

    #[inline]
    fn send_ready(&self) -> bool {
        self.send_queue.len() < self.config.send_window_size as usize
    }

    #[inline]
    fn recv_ready(&self) -> bool {
        !self.recv_queue.is_empty()
    }

    #[inline]
    fn flush_ready(&self) -> bool {
        self.send_queue.is_empty() && self.send_window.is_empty()
    }

    pub fn poll_send(&mut self, cx: &Context, payload: &[u8]) -> Poll<KcpResult<()>> {
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            return Poll::Ready(Err(KcpError::Shutdown(format!(
                "poll_send on a closing kcp core: {}",
                self.close_state.bits,
            ))));
        }

        self.now = now_millis();
        self.last_active = self.now;

        if self.send_ready() {
            let mss = self.config.mss;
            if self.send_queue.is_empty() {
                self.send_queue.push_back(BytesMut::with_capacity(mss));
            }

            let mut cursor = payload;

            while cursor.has_remaining() {
                if self.send_queue.back_mut().unwrap().len() < mss {
                    let back = self.send_queue.back_mut().unwrap();
                    let len = cmp::min(cursor.remaining(), mss - back.len());
                    back.extend_from_slice(&cursor[..len]);
                    cursor.advance(len);
                } else {
                    self.send_queue.push_back(BytesMut::with_capacity(mss));
                }
            }

            Poll::Ready(Ok(()))
        } else {
            let _ = self.flush_notify_tx.try_send(());
            self.send_waker = Some(cx.waker().clone());
            log::trace!("poll_send pending");
            Poll::Pending
        }
    }

    pub fn poll_recv(&mut self, cx: &Context) -> Poll<KcpResult<VecDeque<Bytes>>> {
        self.now = now_millis();
        self.last_active = self.now;

        if self.recv_ready() {
            let queue = self.recv_queue.clone();
            self.recv_queue.clear();
            return Poll::Ready(Ok(queue));
        } else {
            if self.close_state.contains(CloseFlags::RX_CLOSED) {
                return Poll::Ready(Err(KcpError::Shutdown(format!(
                    "poll_recv on a closing kcp core: {}",
                    self.close_state.bits,
                ))));
            }
            log::trace!("poll_recv pending");
            self.recv_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_flush(&mut self, cx: &Context) -> Poll<KcpResult<()>> {
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            return Poll::Ready(Err(KcpError::Shutdown(format!(
                "poll_recv on a closing kcp core: {}",
                self.close_state.bits,
            ))));
        }

        self.now = now_millis();
        self.last_active = self.now;

        if self.flush_ready() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn try_close(&mut self) -> KcpResult<()> {
        self.now = now_millis();
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            Err(KcpError::Shutdown("kcp core is shutting down".to_string()))
        } else {
            log::trace!("trying to close kcp core..");
            self.close_state.set(CloseFlags::TX_CLOSING, true);
            self.send_queue.push_back(BytesMut::new());
            Ok(())
        }
    }

    pub fn poll_close(&mut self, cx: &Context) -> Poll<KcpResult<()>> {
        self.now = now_millis();
        if !self.close_state.contains(CloseFlags::TX_CLOSING) {
            self.close_state.set(CloseFlags::TX_CLOSING, true);
            // Empty payload
            self.send_queue.push_back(BytesMut::new());
            self.close_waker = Some(cx.waker().clone());
            log::trace!("poll_close set close flag..");
            Poll::Pending
        } else if self.close_state.contains(CloseFlags::CLOSED) {
            log::trace!("poll_close ready");
            Poll::Ready(Ok(()))
        } else {
            // TX_CLOSED/TX_CLOSING, !RX_CLOSED
            // Just waiting for notification
            if let Some(waker) = &self.close_waker {
                if !cx.waker().will_wake(waker) {
                    unreachable!();
                }
            }

            self.close_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    #[inline]
    async fn encode_segment<IO: KcpIo>(
        segment: &KcpSegment,
        buffer: &mut Vec<u8>,
        io: &IO,
        mtu: usize,
    ) -> KcpResult<()> {
        if buffer.len() + segment.encoded_len() > mtu {
            io.send_packet(buffer).await?;
            buffer.clear();
        }
        segment.encode(buffer);
        Ok(())
    }

    async fn flush_ack<IO: KcpIo>(&mut self, writer: &IO) -> KcpResult<()> {
        if self.ack_list.is_empty() {
            return Ok(());
        }
        let mut data = BytesMut::new();
        data.resize(4 * 2 * self.ack_list.len(), 0);

        let mut cursor = &mut data[..];

        for (timestamp, sequence) in &self.ack_list {
            cursor.put_u32_le(*timestamp);
            cursor.put_u32_le(*sequence);
        }

        let segment = KcpSegment {
            stream_id: self.stream_id,
            command: CMD_ACK,
            recv_window_size: self.recv_window_unused(),
            recv_next: self.recv_next,
            sequence: 0,
            timestamp: 0,
            data: data.freeze(),
        };
        Self::encode_segment(&segment, &mut self.buffer, writer, self.config.mtu).await?;
        self.ack_list.clear();
        Ok(())
    }

    async fn flush_ping<IO: KcpIo>(&mut self, writer: &IO) -> KcpResult<()> {
        if i32diff(self.now, self.ping_ts) >= 0 {
            log::trace!("flushing ping");
            self.ping_ts = self.now + self.config.keep_alive_interval;
            let segment = KcpSegment {
                stream_id: self.stream_id,
                command: CMD_PING,
                recv_window_size: self.recv_window_unused(),
                recv_next: self.recv_next,
                sequence: self.send_next,
                timestamp: self.now,
                data: Bytes::new(),
            };
            Self::encode_segment(&segment, &mut self.buffer, writer, self.config.mtu).await?;
        }
        Ok(())
    }

    #[inline]
    fn recv_window_unused(&self) -> u16 {
        if self.recv_queue.len() < self.config.recv_window_size as usize {
            self.config.recv_window_size - self.recv_queue.len() as u16
        } else {
            0
        }
    }

    pub async fn flush<IO: KcpIo>(&mut self, io: &IO) -> KcpResult<()> {
        self.now = now_millis();

        if i32diff(self.now, self.last_measure) >= 500 && self.push_counter >= 100 {
            if let Congestion::LossTolerance = self.config.congestion {
                let loss_rate = self.rexmit_counter * 100 / self.push_counter;
                if loss_rate >= 15 {
                    self.congestion_window_size -= self.congestion_window_size / 4;
                } else if loss_rate <= 5 {
                    self.congestion_window_size += self.congestion_window_size / 4;
                }
                log::trace!("loss_rate = {}", loss_rate);
                self.congestion_window_size = bound(
                    MIN_WINDOW_SIZE,
                    self.congestion_window_size,
                    self.config.send_window_size,
                );
            }

            self.last_measure = self.now;
            self.rexmit_counter = 0;
            self.push_counter = 0;
        }

        // Keep working until the core is fully closed
        if self.close_state.contains(CloseFlags::CLOSED) {
            if self.close_moment == 0 {
                // Keep running for a while to ACK
                let wait = bound(100, self.rto * 2, self.config.timeout);
                self.close_moment = self.now + wait;
            } else if i32diff(self.now, self.close_moment) >= 0 {
                // It's time to shutdown
                self.force_close();
                return Err(KcpError::Shutdown("flushing a closed kcp core".to_string()));
            }
        }

        if i32diff(self.now, self.last_active) > self.config.timeout as i32 {
            // Inactive for a long time, shut it down immediately
            self.force_close();
            return Err(KcpError::Shutdown(
                "flushing a timeout kcp core".to_string(),
            ));
        }

        self.flush_ack(io).await?;
        self.flush_ping(io).await?;

        let mut final_window_size = cmp::min(self.config.send_window_size, self.remote_window_size);
        match self.config.congestion {
            Congestion::None => {}
            _ => {
                final_window_size = cmp::min(final_window_size, self.congestion_window_size);
            }
        }

        let recv_window_unused = self.recv_window_unused();

        // Push data into sending window
        while i32diff(self.send_next, self.send_unack + final_window_size as u32) < 0 {
            match self.send_queue.pop_front() {
                Some(data) => {
                    let segment = KcpSegment {
                        stream_id: self.stream_id,
                        command: CMD_PUSH,
                        sequence: self.send_next,
                        timestamp: self.now,
                        recv_window_size: recv_window_unused,
                        recv_next: self.recv_next,
                        data: data.freeze(),
                    };
                    let sending_segment = SendingKcpSegment {
                        segment,
                        rexmit_timestamp: self.now,
                        rto: self.rto,
                        fast_rexmit_counter: 0,
                        rexmit_counter: 0,
                    };
                    self.send_next += 1;
                    self.send_window.push_back(sending_segment);
                }
                None => {
                    break;
                }
            }
        }

        let fast_rexmit_thresh = self.config.fast_rexmit_thresh;

        let rexmit_delay = if self.config.nodelay {
            0
        } else {
            self.rto >> 3
        };

        let mut rexmit = 0;
        let mut fast_rexmit = 0;

        for sending_segment in &mut self.send_window {
            let mut need_send = false;
            if sending_segment.rexmit_counter == 0 {
                // First time
                sending_segment.rto = self.rto;
                sending_segment.rexmit_timestamp = self.now + self.rto + rexmit_delay;
                need_send = true;
            } else if i32diff(self.now, sending_segment.rexmit_timestamp) >= 0 {
                // Timeout, rexmit
                need_send = true;
                rexmit += 1;
                self.rexmit_counter += 1;
                if self.config.nodelay {
                    // ~ 1.5x rto
                    sending_segment.rto += self.rto / 2;
                } else {
                    // ~ 2x rto
                    sending_segment.rto += self.rto;
                }
                sending_segment.rexmit_timestamp = self.now + sending_segment.rto;
            } else if sending_segment.fast_rexmit_counter > fast_rexmit_thresh {
                // Fast rexmit
                need_send = true;
                fast_rexmit += 1;
                sending_segment.fast_rexmit_counter = 0;
            }

            if need_send {
                self.push_counter += 1;
                sending_segment.rexmit_counter += 1;
                sending_segment.segment.timestamp = self.now;
                sending_segment.segment.recv_window_size = recv_window_unused;
                Self::encode_segment(
                    &sending_segment.segment,
                    &mut self.buffer,
                    io,
                    self.config.mtu,
                )
                .await?;
                if sending_segment.rexmit_counter >= self.config.max_rexmit_time {
                    log::trace!("retransmitted for too many times, closed");
                    self.force_close();
                    return Err(KcpError::NoResponse);
                }
            }
        }

        if !self.buffer.is_empty() {
            io.send_packet(&mut self.buffer).await?;
            self.buffer.clear();
        }

        if let Congestion::KcpReno = self.config.congestion {
            let mss = self.config.mss;
            if fast_rexmit > 0 {
                // Some ACK packets was skipped
                let inflight_packet = (self.send_next - self.send_unack) as u16;
                self.slow_start_thresh = cmp::max(inflight_packet / 2, SSTHRESH_MIN);
                self.congestion_window_size =
                    self.slow_start_thresh + self.config.fast_rexmit_thresh as u16;
                self.congestion_window_bytes = self.congestion_window_size as usize * mss;
                log::trace!(
                    "fast resent, cwnd = {}, incr = {}",
                    self.congestion_window_size,
                    self.congestion_window_bytes
                );
            }

            if rexmit > 0 {
                // Packet lost
                self.slow_start_thresh = cmp::max(self.congestion_window_size / 2, SSTHRESH_MIN);
                self.congestion_window_size = 1;
                self.congestion_window_bytes = mss;
                log::trace!(
                    "packet lost, cwnd = {}, incr = {}",
                    self.congestion_window_size,
                    self.congestion_window_bytes
                );
            }
        }

        self.try_wake_stream();
        Ok(())
    }

    #[inline]
    pub fn get_interval(&self) -> u32 {
        let mut interval = self.config.max_interval;
        for i in &self.send_window {
            let delta = i32diff(self.now, i.rexmit_timestamp);
            if delta < 0 {
                return self.config.min_interval;
            }
            interval = cmp::min(delta as u32, interval);
        }
        interval = cmp::max(interval, self.config.min_interval);
        log::trace!("dynamic interval = {}", interval);
        interval
    }

    pub fn new(
        stream_id: u16,
        config: Arc<KcpConfig>,
        flush_notify_tx: Sender<()>,
    ) -> KcpResult<Self> {
        config.check()?;
        let now = now_millis();
        Ok(KcpCore {
            stream_id,
            config: config.clone(),
            send_queue: VecDeque::with_capacity(config.send_window_size as usize),
            send_window: VecDeque::with_capacity(config.send_window_size as usize),
            recv_queue: VecDeque::with_capacity(config.recv_window_size as usize),
            recv_window: HashMap::with_capacity(config.recv_window_size as usize),
            ack_list: VecDeque::with_capacity(config.recv_window_size as usize),
            send_unack: 0,
            send_next: 0,
            recv_next: 0,

            remote_window_size: config.recv_window_size,
            congestion_window_size: config.send_window_size,
            congestion_window_bytes: config.mss,
            slow_start_thresh: SSTHRESH_MIN,

            rto: RTO_INIT,
            srtt: 0,
            rttval: 0,

            now: now,
            ping_ts: 0,

            buffer: Vec::with_capacity(config.mtu * 2),

            send_waker: None,
            recv_waker: None,
            flush_waker: None,
            flush_notify_tx,
            close_state: CloseFlags::empty(),
            close_moment: 0,
            close_waker: None,

            last_active: now,

            push_counter: 0,
            rexmit_counter: 0,
            last_measure: now,
        })
    }
}

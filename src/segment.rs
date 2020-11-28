use bytes::{Buf, BufMut, Bytes};

use crate::error::{KcpError, KcpResult};

pub const HEADER_SIZE: usize = 2 + 1 + 2 + 4 + 4 + 4 + 2;
pub const CMD_PUSH: u8 = 1;
pub const CMD_ACK: u8 = 2;
pub const CMD_PING: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KcpSegment {
    pub stream_id: u16,
    pub command: u8,
    pub recv_window_size: u16,
    pub timestamp: u32,
    pub sequence: u32,
    pub recv_next: u32,
    pub data: Bytes,
}

impl KcpSegment {
    fn check_command(commmand: u8) -> KcpResult<()> {
        match commmand {
            CMD_ACK | CMD_PUSH | CMD_PING => Ok(()),
            _ => Err(KcpError::UnsupportCmd(commmand)),
        }
    }

    #[inline]
    pub fn peek_stream_id(mut packet: &[u8]) -> u16 {
        packet.get_u16_le()
    }

    pub fn decode(mut packet: &[u8]) -> KcpResult<Self> {
        let stream_id = packet.get_u16_le();
        let command = packet.get_u8();
        Self::check_command(command)?;
        let recv_window_size = packet.get_u16_le();
        let timestamp = packet.get_u32_le();
        let sequence = packet.get_u32_le();
        let recv_next = packet.get_u32_le();
        let len = packet.get_u16_le();
        if packet.remaining() < len as usize {
            return Err(KcpError::InvalidSegmentDataSize(
                len as usize,
                packet.remaining(),
            ));
        }

        let data = packet.copy_to_bytes(len as usize);

        if command == CMD_ACK && (len == 0 || len % 8 != 0) {
            return Err(KcpError::InvalidSegmentDataSize(8, len as usize));
        }

        let segment = Self {
            stream_id,
            command,
            recv_window_size,
            timestamp,
            sequence,
            recv_next,
            data,
        };
        Ok(segment)
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.put_u16_le(self.stream_id);
        buf.put_u8(self.command);
        buf.put_u16_le(self.recv_window_size);
        buf.put_u32_le(self.timestamp);
        buf.put_u32_le(self.sequence);
        buf.put_u32_le(self.recv_next);
        buf.put_u16_le(self.data.len() as u16);
        buf.put_slice(&self.data);
    }

    #[inline]
    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.data.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn encode_decode() {
        let segment1 = KcpSegment {
            stream_id: 1234,
            command: CMD_PUSH,
            recv_window_size: 100,
            timestamp: 1,
            recv_next: 123,
            sequence: 2,
            data: Bytes::copy_from_slice(b"hello_world!"),
        };

        let mut buf = Vec::new();
        segment1.encode(&mut buf);
        assert_eq!(buf.len(), segment1.encoded_len());

        let segment2 = KcpSegment::decode(&buf).unwrap();

        assert_eq!(segment1, segment2);
    }
}

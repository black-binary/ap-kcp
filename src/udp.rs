#[async_trait::async_trait]
impl crate::KcpIo for smol::net::UdpSocket {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        self.send(buf).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()> {
        let size = self.recv(buf).await?;
        buf.truncate(size);
        Ok(())
    }
}

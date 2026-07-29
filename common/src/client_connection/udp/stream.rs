use super::*;

pub struct UdpClientStream {
    pub(super) flow_id: u64,
    pub(super) open_address: Option<Address>,
    pub(super) stream_id: String,
    pub(super) command_tx: PollSender<ClientCommand>,
    pub(super) inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub(super) read_buf: Vec<u8>,
    pub(super) read_pos: usize,
    pub(super) close_sent: bool,
}

impl UdpClientStream {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

impl AsyncRead for UdpClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_pos < self.read_buf.len() {
            let datagram_len = self.read_buf.len() - self.read_pos;
            if buf.remaining() < datagram_len {
                return Poll::Ready(Err(short_datagram_buffer_error(
                    buf.remaining(),
                    datagram_len,
                )));
            }
            buf.put_slice(&self.read_buf[self.read_pos..]);
            self.read_pos = self.read_buf.len();
            return Poll::Ready(Ok(()));
        }
        self.read_buf.clear();
        self.read_pos = 0;

        loop {
            match Pin::new(&mut self.inbound_rx).poll_recv(cx) {
                Poll::Ready(Some(data)) if data.is_empty() => continue,
                Poll::Ready(Some(data)) => {
                    self.read_buf = data;
                    if buf.remaining() < self.read_buf.len() {
                        return Poll::Ready(Err(short_datagram_buffer_error(
                            buf.remaining(),
                            self.read_buf.len(),
                        )));
                    }
                    buf.put_slice(&self.read_buf);
                    self.read_pos = self.read_buf.len();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn short_datagram_buffer_error(available: usize, required: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "UDP read buffer is too small for one datagram: available={available}, required={required}"
        ),
    )
}

impl AsyncWrite for UdpClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.command_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let flow_id = self.flow_id;
                let command = match self.open_address.clone() {
                    Some(address) => ClientCommand::OpenData {
                        flow_id,
                        address,
                        data: buf.to_vec(),
                    },
                    None => ClientCommand::Data {
                        flow_id,
                        data: buf.to_vec(),
                    },
                };
                self.command_tx.send_item(command).map_err(|_| {
                    io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭")
                })?;
                self.open_address = None;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "原生 UDP 会话已关闭",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // UDP has no userspace flush boundary. A successful poll_write means the
        // complete datagram was accepted by the bounded session queue.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close_sent {
            return Poll::Ready(Ok(()));
        }
        match self.command_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let flow_id = self.flow_id;
                self.command_tx
                    .send_item(ClientCommand::Close { flow_id })
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::NotConnected, "原生 UDP 会话已关闭")
                    })?;
                self.close_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.close_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for UdpClientStream {
    fn drop(&mut self) {
        if self.close_sent {
            return;
        }
        if let Some(sender) = self.command_tx.get_ref() {
            let _ = sender.try_send(ClientCommand::Close {
                flow_id: self.flow_id,
            });
        }
    }
}

impl Unpin for UdpClientStream {}

use futures::{Sink, stream::SplitSink};
use protocol::{DataPacket, ProxyCodec, ProxyResponse};
use std::task::{Context, Poll};
use std::{pin::Pin, result::Result};
use tokio_util::codec::Framed;

use super::AgentStream;

type FramedWriter = SplitSink<Framed<AgentStream, ProxyCodec>, ProxyResponse>;

pub struct BytesToProxyResponseSink<'a> {
    pub inner: &'a mut FramedWriter,
    pub stream_id: String,
    pub end_sent: bool,
}

impl<'a> Sink<&[u8]> for BytesToProxyResponseSink<'a> {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // 背压由底层 framed writer 决定，避免向 agent 过量缓冲数据。
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: &[u8]) -> Result<(), Self::Error> {
        // 目标侧读到的裸字节被包装回协议 DataPacket。
        let stream_id = self.stream_id.clone();

        // 压缩在编解码层处理
        let packet = DataPacket {
            stream_id,
            data: item.to_vec(),
            is_end: false,
        };
        Pin::new(&mut self.inner).start_send(ProxyResponse::Data(packet))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // flush 直接透传到底层 writer。
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // 关闭时只发送协议内的空 end 包，让 agent 明确知道该 stream 已结束。
        // 不在这里 poll_close 底层 framed writer：legacy TCP relay 是双向半关闭，
        // target->agent 的响应方向结束，不代表 agent->target 方向或承载 TCP 连接
        // 也要立刻关闭。过早关闭承载层会让桌面 TUN 下的 HLS/HTTP2 分片偶发截断。
        if !self.end_sent {
            match Pin::new(&mut self.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let packet = DataPacket {
                        stream_id: self.stream_id.clone(),
                        data: Vec::new(),
                        is_end: true,
                    };
                    Pin::new(&mut self.inner).start_send(ProxyResponse::Data(packet))?;
                    self.end_sent = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // end 包必须 flush 出去；真正关闭底层连接交给 relay 完整结束后的
        // ServerConnection 生命周期处理。
        Pin::new(&mut self.inner).poll_flush(cx)
    }
}

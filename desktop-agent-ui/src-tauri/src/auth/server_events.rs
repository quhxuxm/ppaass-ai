use super::*;

const MAX_SSE_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentServerEventKind {
    Sync,
    ProfileChanged,
    ProfilesChanged,
    KeyRequestChanged,
    AdminKeyRequestsChanged,
}

pub struct AgentServerEventStream {
    response: Response,
    decoder: SseDecoder,
}

impl AgentServerEventStream {
    pub async fn connect(base_url: &str, access_token: &str) -> Result<Self, String> {
        let base_url = normalize_proxy_registry_url(base_url)?;
        let url = endpoint(&base_url, "api/v1/agent/events")?;
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|_| "无法初始化 Agent SSE 客户端".to_string())?;
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .map_err(map_request_error)?;
        if !response.status().is_success() {
            return Err(server_event_http_error(response).await);
        }
        let is_event_stream = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim() == "text/event-stream")
            });
        if !is_event_stream {
            return Err("Proxy Registry SSE 响应类型无效".to_string());
        }
        Ok(Self {
            response,
            decoder: SseDecoder::default(),
        })
    }

    pub async fn next_event(&mut self) -> Result<Option<AgentServerEventKind>, String> {
        loop {
            if let Some(event) = self.decoder.next_event()? {
                return Ok(Some(event));
            }
            let Some(chunk) = self
                .response
                .chunk()
                .await
                .map_err(|_| "Agent SSE 事件流读取失败".to_string())?
            else {
                return Ok(None);
            };
            self.decoder.push(&chunk)?;
        }
    }
}

async fn server_event_http_error(response: Response) -> String {
    let status = response.status();
    match read_bounded_response(response, MAX_NORMAL_RESPONSE_BYTES).await {
        Ok((_, bytes)) => serde_json::from_slice::<ErrorEnvelope>(&bytes)
            .map(|envelope| map_api_error(status, envelope.error))
            .unwrap_or_else(|_| format!("Agent SSE 返回 HTTP {}", status.as_u16())),
        Err(error) => error,
    }
}

#[derive(Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    pending_event: Option<String>,
}

impl SseDecoder {
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), String> {
        if self.buffer.len().saturating_add(chunk.len()) > MAX_SSE_BUFFER_BYTES {
            return Err("Agent SSE 事件过大，已断开连接".to_string());
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    pub fn next_event(&mut self) -> Result<Option<AgentServerEventKind>, String> {
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                if let Some(name) = self.pending_event.take() {
                    if let Some(event) = parse_event_name(&name) {
                        return Ok(Some(event));
                    }
                }
                continue;
            }
            if line[0] == b':' {
                continue;
            }
            if let Some(value) = line.strip_prefix(b"event:") {
                let value = std::str::from_utf8(value)
                    .map_err(|_| "Agent SSE 事件名称不是 UTF-8".to_string())?
                    .trim();
                if value.len() > 64 {
                    return Err("Agent SSE 事件名称过长".to_string());
                }
                self.pending_event = Some(value.to_string());
            }
        }
        Ok(None)
    }
}

fn parse_event_name(value: &str) -> Option<AgentServerEventKind> {
    match value {
        "sync" => Some(AgentServerEventKind::Sync),
        "profile_changed" => Some(AgentServerEventKind::ProfileChanged),
        "profiles_changed" => Some(AgentServerEventKind::ProfilesChanged),
        "key_request_changed" => Some(AgentServerEventKind::KeyRequestChanged),
        "admin_key_requests_changed" => Some(AgentServerEventKind::AdminKeyRequestsChanged),
        _ => None,
    }
}

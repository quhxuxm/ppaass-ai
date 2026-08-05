use std::convert::Infallible;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::{StreamExt, stream};
use tokio::sync::broadcast;

use super::super::*;

const AGENT_EVENT_KEEP_ALIVE_SECONDS: u64 = 15;
const AGENT_EVENT_CONNECTION_SECONDS: u64 = 12 * 60 * 60;

struct EventStreamState {
    account_id: String,
    receiver: broadcast::Receiver<crate::agent_events::AgentServerEvent>,
    deadline: tokio::time::Instant,
}

pub(crate) async fn get_agent_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    validate_native_agent_request(&headers)?;
    let account = authenticate_agent_token(&state, &headers).await?;
    let account_id = account.account_id;
    let initial_revision = state.agent_events.latest_revision();
    let updates = stream::unfold(
        EventStreamState {
            account_id: account_id.clone(),
            receiver: state.agent_events.subscribe(),
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(AGENT_EVENT_CONNECTION_SECONDS),
        },
        |mut stream| async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(stream.deadline) => return None,
                    received = stream.receiver.recv() => match received {
                        Ok(event) if event.is_visible_to(&stream.account_id) => {
                            let item = Event::default()
                                .id(event.revision.to_string())
                                .event(event.kind.as_ref())
                                .data("{}");
                            return Some((Ok(item), stream));
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let item = Event::default().event("sync").data("{}");
                            return Some((Ok(item), stream));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        },
    );
    let initial = stream::once(async move {
        Ok(Event::default()
            .id(initial_revision.to_string())
            .event("sync")
            .data("{}")
            .retry(Duration::from_secs(1)))
    });
    info!(account_id, "Agent SSE 事件流已连接");
    Ok(Sse::new(initial.chain(updates)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(AGENT_EVENT_KEEP_ALIVE_SECONDS))
            .text("keep-alive"),
    ))
}

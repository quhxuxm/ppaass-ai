use super::*;

const OUTBOUND_BATCH_LIMIT: usize = 32;

pub(in crate::native_udp) enum ChannelEvent {
    ConnectResult {
        flow_id: u64,
        response: UdpSessionMessage,
    },
    Closed {
        flow_id: u64,
        reason: Option<String>,
    },
}

pub async fn run_session(
    context: SessionContext,
    mut codec: UdpSessionCodec,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let channel_size = context.config.udp_session_channel_size.max(1);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpSessionMessage>(channel_size);
    let (channel_event_tx, mut channel_event_rx) = mpsc::unbounded_channel::<ChannelEvent>();
    let mut channel_tasks = JoinSet::new();
    let mut channels = HashMap::<u64, ChannelState>::new();
    let mut flow_creation_budget = FlowCreationBudget::new(Instant::now());
    let mut authorization_freshness = AuthorizationFreshness::default();
    let idle_timeout = udp_idle_timeout(&context.config);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let authorization_recheck_interval = Duration::from_secs(
        context
            .config
            .udp_session_authorization_recheck_secs
            .clamp(1, 5),
    );
    let mut authorization_recheck = tokio::time::interval(authorization_recheck_interval);
    authorization_recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` 的首次 tick 会立即完成；握手刚刚已经校验过，先消费它。
    authorization_recheck.tick().await;
    let absolute_expiry = wait_until_expired(context.expires_at);
    tokio::pin!(absolute_expiry);

    loop {
        tokio::select! {
            biased;
            _ = &mut absolute_expiry => {
                debug!(
                    username = %context.username,
                    session = %session_label(&codec.session_id()),
                    "原生 UDP 会话达到认证时的绝对过期时间，主动关闭"
                );
                break;
            }
            _ = authorization_recheck.tick() => {
                // A repository query may wait on I/O or pool capacity. Absolute
                // expiry is an independent upper bound and must remain able to
                // cancel that wait instead of being delayed by revalidation.
                let validation = revalidate_authorization(&context);
                tokio::pin!(validation);
                let validation_result = tokio::select! {
                    biased;
                    _ = &mut absolute_expiry => {
                        debug!(
                            username = %context.username,
                            session = %session_label(&codec.session_id()),
                            "原生 UDP 会话在授权复核期间达到绝对过期时间，主动关闭"
                        );
                        break;
                    }
                    result = &mut validation => result,
                };
                if let Err(error) = validation_result {
                    warn!(
                        username = %context.username,
                        session = %session_label(&codec.session_id()),
                        "原生 UDP 会话授权已失效，主动关闭：{error}"
                    );
                    break;
                }
                authorization_freshness.record_success(Instant::now());
            }
            _ = &mut idle => {
                debug!(
                    "原生 UDP 会话空闲超过 {} 秒，主动清理 session={}",
                    idle_timeout.as_secs(),
                    session_label(&codec.session_id())
                );
                break;
            }
            inbound = inbound_rx.recv() => {
                let Some(datagram) = inbound else { break };
                let message = match codec.decode_datagram(&datagram) {
                    Ok(message) => {
                        // codec 只会在 AEAD 校验成功后提交 replay 序号。分片尚未完整
                        // 也是有效活动；未知、重放或篡改包不得刷新 idle。
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        message
                    }
                    Err(error) => {
                        trace!(
                            "丢弃未通过原生 UDP AEAD/replay 校验的数据报 session={}: {error}",
                            session_label(&codec.session_id())
                        );
                        continue;
                    }
                };
                let Some(message) = message else { continue };
                if session_expired_at(context.expires_at, SystemTime::now()) {
                    debug!(
                        username = %context.username,
                        session = %session_label(&codec.session_id()),
                        "原生 UDP 会话已过期，拒绝继续处理数据"
                    );
                    break;
                }

                match message {
                    UdpSessionMessage::OpenData { flow_id, address, data } => {
                        let admission = classify_flow_admission(
                            channels.contains_key(&flow_id),
                            channels.len(),
                            context.config.udp_session_max_flows,
                        );
                        let decision = decide_flow_open(
                            admission,
                            &mut flow_creation_budget,
                            &mut authorization_freshness,
                            Instant::now(),
                            || revalidate_authorization(&context),
                        )
                        .await;
                        let decision = match decision {
                            Ok(decision) => decision,
                            Err(error) => {
                                warn!(
                                    username = %context.username,
                                    session = %session_label(&codec.session_id()),
                                    "创建原生 UDP flow 时授权已失效，主动关闭会话：{error}"
                                );
                                break;
                            }
                        };
                        match decision {
                            FlowOpenDecision::Existing => {
                                // OpenData is an application datagram, not a retryable
                                // control message. Never deliver a duplicate first packet.
                                continue;
                            }
                            FlowOpenDecision::AtCapacity => {
                                debug!(
                                    flow_id,
                                    limit = context.config.udp_session_max_flows,
                                    session = %session_label(&codec.session_id()),
                                    "原生 UDP 会话 flow 数已达上限，拒绝新 flow"
                                );
                                send_session_message(
                                    &context,
                                    &mut codec,
                                    &connect_response(
                                        flow_id,
                                        Some(format!(
                                            "native UDP session flow limit reached ({})",
                                            context.config.udp_session_max_flows
                                        )),
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            FlowOpenDecision::RateLimited => {
                                debug!(
                                    flow_id,
                                    session = %session_label(&codec.session_id()),
                                    "原生 UDP flow 创建速率超过会话预算，拒绝新 flow"
                                );
                                send_session_message(
                                    &context,
                                    &mut codec,
                                    &connect_response(
                                        flow_id,
                                        Some("native UDP flow creation rate limited".to_string()),
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            FlowOpenDecision::Create => {}
                        }

                        let (input_tx, input_rx) = mpsc::channel(channel_size);
                        input_tx
                            .try_send(data)
                            .expect("new native UDP flow queue has capacity");
                        let worker_context = context.clone();
                        let worker_outbound_tx = outbound_tx.clone();
                        let worker_event_tx = channel_event_tx.clone();
                        let abort_handle = channel_tasks.spawn(async move {
                            run_channel_worker(
                                worker_context,
                                flow_id,
                                address,
                                input_rx,
                                worker_outbound_tx,
                                worker_event_tx,
                            )
                            .await;
                        });
                        channels.insert(
                            flow_id,
                            ChannelState {
                                input_tx: Some(input_tx),
                                abort_handle,
                            },
                        );
                    }
                    UdpSessionMessage::Data { flow_id, data } => {
                        let Some(channel) = channels.get_mut(&flow_id) else {
                            trace!("丢弃未连接 channel 的 UDP 数据 flow_id={flow_id}");
                            continue;
                        };
                        let Some(input_tx) = channel.input_tx.as_ref() else {
                            continue;
                        };
                        match input_tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("UDP channel 入站队列已满，丢弃一个包 flow_id={flow_id}");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                channel.input_tx = None;
                            }
                        }
                    }
                    UdpSessionMessage::Close { flow_id, .. } => {
                        if let Some(channel) = channels.remove(&flow_id) {
                            channel.abort_handle.abort();
                        }
                    }
                    UdpSessionMessage::Ping { token } => {
                        send_session_message(
                            &context,
                            &mut codec,
                            &UdpSessionMessage::Pong { token },
                        )
                        .await?;
                    }
                    UdpSessionMessage::Pong { .. }
                    | UdpSessionMessage::ConnectResponse { .. } => {
                        trace!("proxy 收到方向错误的原生 UDP 会话消息，已忽略");
                    }
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(message) = outbound else { continue };
                send_session_message(&context, &mut codec, &message).await?;
                // Amortize select/task wakeups for bursty target responses while
                // keeping receive, expiry, and authorization checks responsive.
                for _ in 1..OUTBOUND_BATCH_LIMIT {
                    let Ok(message) = outbound_rx.try_recv() else { break };
                    send_session_message(&context, &mut codec, &message).await?;
                }
            }
            event = channel_event_rx.recv() => {
                let Some(event) = event else { continue };
                match event {
                    ChannelEvent::ConnectResult { flow_id, response } => {
                        let Some(channel) = channels.get_mut(&flow_id) else { continue };
                        let success = matches!(
                            response,
                            UdpSessionMessage::ConnectResponse { success: true, .. }
                        );
                        if !success {
                            channel.input_tx = None;
                        }
                        send_session_message(&context, &mut codec, &response).await?;
                    }
                    ChannelEvent::Closed { flow_id, reason } => {
                        if channels.remove(&flow_id).is_some() {
                            send_session_message(
                                &context,
                                &mut codec,
                                &UdpSessionMessage::Close { flow_id, reason },
                            )
                            .await?;
                        }
                    }
                }
            }
            joined = channel_tasks.join_next(), if !channel_tasks.is_empty() => {
                if let Some(Err(error)) = joined
                    && !error.is_cancelled()
                {
                    warn!("proxy 原生 UDP channel worker 异常结束：{error}");
                }
            }
        }
    }

    for (_, channel) in channels.drain() {
        channel.abort_handle.abort();
    }
    channel_tasks.abort_all();
    while channel_tasks.join_next().await.is_some() {}
    Ok(())
}

use super::*;

pub(super) async fn run_blocked_target_connect_range_regression(agent_addr: &str) -> Result<()> {
    let file_size = 8 * 1024 * 1024_u64;
    let chunk_size = 64 * 1024_u64;
    let chunk_count = 24_u64;

    let mut blocker_handles = Vec::with_capacity(18);
    for worker_id in 0..18 {
        let agent_addr = agent_addr.to_string();
        blocker_handles.push(tokio::spawn(async move {
            run_blocked_target_connect_attempt(agent_addr, worker_id).await;
        }));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut download_handles = Vec::with_capacity(chunk_count as usize);
    for chunk_idx in 0..chunk_count {
        let agent_addr = agent_addr.to_string();
        download_handles.push(tokio::spawn(async move {
            let range_start = chunk_idx * chunk_size;
            let range_end = range_start + chunk_size - 1;

            if chunk_idx % 2 == 0 {
                verify_http_range_chunk(&agent_addr, file_size, range_start, range_end).await
            } else {
                verify_connect_range_chunk(&agent_addr, file_size, range_start, range_end).await
            }
        }));
    }

    let mut errors = Vec::new();
    for handle in download_handles {
        match handle.await.context("range download task panicked")? {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    for handle in blocker_handles {
        let _ = handle.await;
    }

    anyhow::ensure!(
        errors.is_empty(),
        "分片下载在阻塞连接扰动下失败：{}",
        errors.join("; ")
    );

    Ok(())
}

pub(super) async fn run_fluctuating_target_range_regression(agent_addr: &str) -> Result<()> {
    let target_authority = "127.0.0.1:9090".to_string();
    let file_size = 4 * 1024 * 1024_u64;
    let chunk_size = 48 * 1024_u64;
    let chunk_count = 12_u64;

    let mut handles = Vec::with_capacity(chunk_count as usize);
    for chunk_idx in 0..chunk_count {
        let agent_addr = agent_addr.to_string();
        let target_authority = target_authority.clone();
        handles.push(tokio::spawn(async move {
            let range_start = chunk_idx * chunk_size + (chunk_idx % 5);
            let range_end = range_start + chunk_size - 1;

            let check = match chunk_idx % 3 {
                0 => {
                    verify_fluctuating_http_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
                1 => {
                    verify_fluctuating_connect_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
                _ => {
                    verify_fluctuating_socks5_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
            };

            check.with_context(|| {
                format!("fluctuating target range {range_start}-{range_end} failed")
            })
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, handle)
            .await
            .context("fluctuating range download task timeout")?
            .context("fluctuating range download task panicked")?
        {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    anyhow::ensure!(
        errors.is_empty(),
        "分片下载在网络波动目标下失败：{}",
        errors.join("; ")
    );

    Ok(())
}

pub(super) async fn run_browser_like_reused_connection_regression(agent_addr: &str) -> Result<()> {
    tokio::time::timeout(BROWSER_LIKE_TIMEOUT, async {
        verify_http_repeated_range_sequence(agent_addr, 6, 5 * 1024 * 1024, 40 * 1024)
            .await
            .context("HTTP repeated range sequence failed")?;
        verify_connect_keepalive_range_sequence(agent_addr, 6, 5 * 1024 * 1024, 40 * 1024)
            .await
            .context("CONNECT keep-alive range sequence failed")?;
        Ok(())
    })
    .await
    .context("browser-like reused connection regression timed out")?
}

pub(super) async fn run_http2_multiplexed_tunnel_regression(agent_addr: &str) -> Result<()> {
    tokio::time::timeout(BROWSER_LIKE_TIMEOUT, async {
        let mut connect_stream = TcpStream::connect(agent_addr)
            .await
            .context("failed to connect to agent for H2 CONNECT test")?;
        write_connect_request(&mut connect_stream, "127.0.0.1:9093").await?;
        read_connect_ok_response(&mut connect_stream).await?;
        verify_h2_multiplexed_range_sequence(
            connect_stream,
            "H2 over CONNECT",
            8,
            6 * 1024 * 1024,
            48 * 1024,
        )
        .await?;

        let mut socks_stream = TcpStream::connect(agent_addr)
            .await
            .context("failed to connect to agent for H2 SOCKS5 test")?;
        async_socks5::connect(&mut socks_stream, ("127.0.0.1".to_string(), 9093), None)
            .await
            .context("failed to connect through SOCKS5 for H2 test")?;
        verify_h2_multiplexed_range_sequence(
            socks_stream,
            "H2 over SOCKS5",
            8,
            6 * 1024 * 1024,
            48 * 1024,
        )
        .await
    })
    .await
    .context("HTTP/2 multiplexed tunnel regression timed out")?
}

pub(super) async fn run_client_cancellation_regression(agent_addr: &str) -> Result<()> {
    let file_size = 6 * 1024 * 1024_u64;
    let chunk_size = 256 * 1024_u64;
    let mut cancel_handles = Vec::new();

    for idx in 0..18_u64 {
        let agent_addr = agent_addr.to_string();
        cancel_handles.push(tokio::spawn(async move {
            let start = idx * chunk_size;
            let end = start + chunk_size - 1;
            match idx % 3 {
                0 => cancel_http_range_after_partial_body(&agent_addr, file_size, start, end).await,
                1 => {
                    cancel_connect_range_after_partial_body(&agent_addr, file_size, start, end)
                        .await
                }
                _ => {
                    cancel_socks5_range_after_partial_body(&agent_addr, file_size, start, end).await
                }
            }
        }));
    }

    let mut errors = Vec::new();
    for handle in cancel_handles {
        match handle.await.context("cancellation task panicked")? {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }
    anyhow::ensure!(errors.is_empty(), "取消请求失败：{}", errors.join("; "));

    verify_mixed_protocol_range_downloads(agent_addr, file_size, 32 * 1024, 12)
        .await
        .context("post-cancellation range verification failed")
}

pub(super) async fn run_slow_client_backpressure_regression(agent_addr: &str) -> Result<()> {
    let file_size = 7 * 1024 * 1024_u64;
    let chunk_size = 96 * 1024_u64;
    let mut handles = Vec::new();

    for idx in 0..9_u64 {
        let agent_addr = agent_addr.to_string();
        handles.push(tokio::spawn(async move {
            let start = idx * chunk_size + (idx % 7);
            let end = start + chunk_size - 1;
            match idx % 3 {
                0 => slow_read_http_range(&agent_addr, file_size, start, end).await,
                1 => slow_read_connect_range(&agent_addr, file_size, start, end).await,
                _ => slow_read_socks5_range(&agent_addr, file_size, start, end).await,
            }
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match tokio::time::timeout(BROWSER_LIKE_TIMEOUT, handle)
            .await
            .context("slow client task timed out")?
            .context("slow client task panicked")?
        {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    anyhow::ensure!(errors.is_empty(), "慢读请求失败：{}", errors.join("; "));

    verify_mixed_protocol_range_downloads(agent_addr, file_size, 32 * 1024, 9)
        .await
        .context("post-slow-client range verification failed")
}

pub(super) async fn run_connection_churn_regression(agent_addr: &str) -> Result<()> {
    tokio::time::timeout(BROWSER_LIKE_TIMEOUT, async {
        let churn_file_size = 8 * 1024 * 1024_u64;

        let mut handles = Vec::new();
        for idx in 0..24_u64 {
            let agent_addr = agent_addr.to_string();
            handles.push(tokio::spawn(async move {
                let chunk_size = 64 * 1024_u64;
                let start = idx * chunk_size + (idx % 11);
                let end = start + chunk_size - 1;

                match idx % 6 {
                    0 => slow_read_http_range(&agent_addr, churn_file_size, start, end).await,
                    1 => slow_read_connect_range(&agent_addr, churn_file_size, start, end).await,
                    2 => slow_read_socks5_range(&agent_addr, churn_file_size, start, end).await,
                    3 => {
                        cancel_http_range_after_partial_body(
                            &agent_addr,
                            churn_file_size,
                            start,
                            end,
                        )
                        .await
                    }
                    4 => {
                        cancel_connect_range_after_partial_body(
                            &agent_addr,
                            churn_file_size,
                            start,
                            end,
                        )
                        .await
                    }
                    _ => {
                        run_blocked_target_connect_attempt(agent_addr, idx as usize).await;
                        Ok(())
                    }
                }
            }));
        }

        let mut errors = Vec::new();
        for handle in handles {
            match handle.await.context("connection churn task panicked")? {
                Ok(()) => {}
                Err(err) => errors.push(err.to_string()),
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "连接 churn 子任务失败：{}",
            errors.join("; ")
        );

        verify_mixed_protocol_range_downloads(agent_addr, churn_file_size, 24 * 1024, 15)
            .await
            .context("post-churn range verification failed")
    })
    .await
    .context("connection churn regression timed out")?
}

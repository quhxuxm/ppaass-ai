use crate::models::{NetworkInterfaceTraffic, NetworkTrafficSnapshot};
use crate::process_util::current_time_millis;

#[cfg(windows)]
use crate::models::ServiceRequest;
#[cfg(windows)]
use crate::windows_service::send_service_request;

pub(crate) fn get_network_traffic_snapshot_inner() -> Result<NetworkTrafficSnapshot, String> {
    #[cfg(windows)]
    if let Ok(response) = send_service_request(&ServiceRequest::Traffic) {
        if response.ok {
            if let Some(traffic) = response.traffic {
                return Ok(traffic);
            }
        }
    }

    Ok(agent_traffic_snapshot())
}

pub(crate) fn get_dns_resolution_records_inner(
) -> Result<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>, String> {
    #[cfg(windows)]
    {
        let response = send_service_request(&ServiceRequest::DnsRecords)?;
        if response.ok {
            return Ok(response.dns_records.unwrap_or_default());
        }
        return Err(response
            .error
            .unwrap_or_else(|| "Agent 服务 DNS 解析记录请求失败".to_string()));
    }

    #[cfg(not(windows))]
    Ok(desktop_agent_be::telemetry::dns_resolution_records())
}

pub(crate) fn agent_traffic_snapshot() -> NetworkTrafficSnapshot {
    let traffic = desktop_agent_be::telemetry::traffic_snapshot();

    NetworkTrafficSnapshot {
        sampled_at_ms: current_time_millis(),
        total_received_bytes: traffic.inbound_bytes,
        total_transmitted_bytes: traffic.outbound_bytes,
        interfaces: vec![NetworkInterfaceTraffic {
            name: "Agent".to_string(),
            received_bytes: traffic.inbound_bytes,
            transmitted_bytes: traffic.outbound_bytes,
        }],
    }
}

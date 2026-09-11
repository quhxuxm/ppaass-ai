use super::*;

mod general;
mod large_download;
mod max_throughput;
mod quic;
mod tcp;
mod udp;

pub(super) use general::generate_markdown_report;
pub(super) use large_download::generate_large_download_markdown_report;
pub(super) use max_throughput::generate_max_throughput_markdown_report;
pub(super) use quic::generate_quic_markdown_report;
pub(super) use tcp::generate_tcp_markdown_report;
pub(super) use udp::generate_udp_markdown_report;

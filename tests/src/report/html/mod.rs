use super::*;

mod general;
mod large_download;
mod quic;
mod tcp;
mod udp;

pub(super) use general::generate_html_report;
pub(super) use large_download::generate_large_download_html_report;
pub(super) use quic::generate_quic_html_report;
pub(super) use tcp::generate_tcp_html_report;
pub(super) use udp::generate_udp_html_report;

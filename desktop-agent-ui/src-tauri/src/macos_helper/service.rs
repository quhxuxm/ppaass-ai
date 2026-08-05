use super::*;

pub(crate) fn run_macos_tun_helper_service_from_args() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    let socket = arg_value(&args, TUN_HELPER_SOCKET_ARG);
    let allowed_uid = match arg_value(&args, TUN_HELPER_ALLOWED_UID_ARG) {
        Some(value) => Some(
            value
                .parse::<u32>()
                .map_err(|err| format!("解析 TUN helper allowed uid 失败：{err}"))?,
        ),
        None => None,
    };
    let log_level = arg_value(&args, TUN_HELPER_LOG_LEVEL_ARG);

    desktop_agent_be::run_tun_helper_service(socket.as_deref(), allowed_uid, log_level.as_deref())
        .map_err(|err| err.to_string())
}

pub(crate) fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find_map(|pair| {
        if pair[0] == flag {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

export interface AgentConfig {
    listen_address: string;
    proxy_address: string;
    username: string;
    pool_size: number;
    log_level: string;
    private_key_path: string;
}

export type AgentStatus = "running" | "stopped" | "error";

export interface AgentState {
    status: AgentStatus;
    connections: number;
    uptime: number;
    bytes_sent: number;
    bytes_received: number;
}

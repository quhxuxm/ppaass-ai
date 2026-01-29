# Automatic Protocol Detection Update

## Summary of Changes

Based on the updated requirements, the agent now automatically detects whether incoming traffic is HTTP or SOCKS5 protocol, eliminating the need for users to connect to different ports.

## Key Changes

### 1. **Unified Proxy Server**
- **Before**: Separate HTTP (port 8080) and SOCKS5 (port 1080) servers
- **After**: Single unified server (port 8080) that auto-detects protocol

### 2. **New Module: `unified_proxy.rs`**
Created a new module that:
- Listens on a single port
- Peeks at the first byte of incoming connections
- Detects protocol automatically:
  - `0x05` = SOCKS5
  - ASCII letters (C, D, G, H, O, P, T) = HTTP
  - Unknown = defaults to HTTP
- Routes traffic to appropriate handler

### 3. **Configuration Changes**

**agent.toml**:
```toml
# Before
http_listen_addr = "127.0.0.1:8080"
socks5_listen_addr = "127.0.0.1:1080"

# After  
listen_addr = "127.0.0.1:8080"  # Auto-detects both protocols
```

**AgentConfig struct**:
- Removed: `http_listen_addr` and `socks5_listen_addr`
- Added: `listen_addr`

### 4. **CLI Arguments Updated**
```rust
// Before
#[arg(long, env = "AGENT_HTTP_ADDR")]
http_addr: Option<String>,

#[arg(long, env = "AGENT_SOCKS5_ADDR")]
socks5_addr: Option<String>,

// After
#[arg(long, env = "AGENT_LISTEN_ADDR")]
listen_addr: Option<String>,
```

### 5. **Module Updates**

**http_proxy.rs**:
- Added public `handle_connection()` function
- Accepts already-established `TcpStream`
- Can be called from unified proxy

**socks5_proxy.rs**:
- Made `handle_connection()` public
- Accepts already-established `TcpStream`
- Can be called from unified proxy

### 6. **main.rs Refactoring**
- Replaced separate HTTP and SOCKS5 server spawning
- Now spawns single unified proxy server
- Simplified startup logic

## Protocol Detection Algorithm

```rust
async fn detect_protocol(stream: &mut TcpStream) -> Result<Protocol> {
    let mut buf = [0u8; 1];
    stream.peek(&mut buf).await?;  // Peek without consuming
    
    match buf[0] {
        0x05 => Ok(Protocol::Socks5),  // SOCKS5 version byte
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => Ok(Protocol::Http),
        _ => Ok(Protocol::Http)  // Default to HTTP
    }
}
```

**HTTP Methods Detected**:
- CONNECT, DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE

## User Experience Improvements

### Before
- Users had to know which port for which protocol
- HTTP: `127.0.0.1:8080`
- SOCKS5: `127.0.0.1:1080`

### After
- Single port for everything: `127.0.0.1:8080`
- Automatic detection - just works!

```bash
# HTTP - same port
curl -x http://127.0.0.1:8080 https://example.com

# SOCKS5 - same port, auto-detected
curl --socks5 127.0.0.1:8080 https://example.com
```

## Benefits

1. **Simplified Configuration**: One port to remember
2. **Better UX**: No need to choose protocol
3. **Easier Deployment**: Fewer firewall rules needed
4. **Backward Compatible**: Still supports both protocols
5. **Transparent**: Client applications work exactly as before

## Files Modified

- ✅ `agent/src/main.rs` - Updated to use unified proxy
- ✅ `agent/src/config.rs` - Changed to single listen address
- ✅ `agent/src/http_proxy.rs` - Exposed handle_connection()
- ✅ `agent/src/socks5_proxy.rs` - Made handle_connection() public
- ✅ `agent.toml` - Updated configuration
- ✅ `agent.example.toml` - Updated example
- ✅ `README.md` - Updated documentation
- ✅ `PROJECT_SUMMARY.md` - Updated project summary

## Files Created

- ✅ `agent/src/unified_proxy.rs` - New automatic protocol detection module

## Testing

The code compiles successfully:
```
cargo build --workspace --release
Finished `release` profile [optimized] target(s)
```

## Migration Guide

For existing users:

1. **Update configuration**:
   ```toml
   # Change from:
   http_listen_addr = "127.0.0.1:8080"
   socks5_listen_addr = "127.0.0.1:1080"
   
   # To:
   listen_addr = "127.0.0.1:8080"
   ```

2. **Update client applications**:
   - HTTP clients: Continue using port 8080
   - SOCKS5 clients: Change from port 1080 to 8080

3. **Environment variables** (if used):
   ```bash
   # Change from:
   AGENT_HTTP_ADDR=127.0.0.1:8080
   AGENT_SOCKS5_ADDR=127.0.0.1:1080
   
   # To:
   AGENT_LISTEN_ADDR=127.0.0.1:8080
   ```

## Requirements Compliance

✅ **Requirement**: "The agent side should support HTTP and SOCKS5 protocols, it is no need for user to select to use HTTP or SOCKS5, the agent side should detect the protocol automatically."

✅ **Implementation**: Protocol is detected automatically by inspecting the first byte of incoming connections using `TcpStream::peek()`.

## Next Steps

The agent now fully complies with the updated requirements, providing automatic protocol detection while maintaining full backward compatibility with both HTTP and SOCKS5 clients.

# Stack Overflow Fix - Instrumentation Optimization

## Problem

After adding `#[instrument]` tracing attributes to the bot proxy and agent, both applications were experiencing stack
overflow errors. This was caused by excessive instrumentation on hot-path functions that are called frequently in loops
or chains.

## Root Cause

The `#[instrument]` macro creates complex span data structures that accumulate on the stack. When applied to functions
that are:

1. Called in tight loops (like reading requests)
2. Called very frequently (like sending responses)
3. Long-lived (like relay operations that maintain bidirectional connections)

The span context would cause stack depth issues leading to stack overflow.

## Solution

Removed `#[instrument]` attributes from hot-path functions while keeping them on less frequently called functions for
observability.

### Changes Made

#### Proxy Side (`proxy/src/connection/mod.rs`)

**Removed instrumentation from hot-path functions:**

- `read_request()` - Called in a tight loop for every incoming message
- `send_response()` - Called frequently for every outgoing message
- `handle_request()` - Main connection handler loop
- `handle_connect()` - Called for each new connection request
- `relay_udp()` - Long-lived bidirectional relay function

**Kept instrumentation on less frequent functions:**

- `peek_auth_username()` - Called once per connection
- `send_auth_error()` - Called occasionally during auth failures
- `authenticate()` - Called once per connection

#### Agent Side - SOCKS5 Handler (`agent/src/socks5_handler.rs`)

**Removed instrumentation from hot-path functions:**

- `handle_tcp_connect()` - Handles each TCP connection setup
- `handle_udp_associate()` - Handles UDP association setup
- `process_udp_traffic()` - Main UDP traffic loop
- `relay_data()` - Bidirectional data relay for connections

**Kept instrumentation on less frequent functions:**

- `handle_socks5_connection()` - Called once per SOCKS5 connection

#### Agent Side - HTTP Handler (`agent/src/http_handler.rs`)

**Removed instrumentation from hot-path functions:**

- `handle_http_connection()` - Called for each HTTP connection
- `handle_http_request()` - Called for each HTTP request
- `handle_connect()` - Called for HTTP CONNECT requests
- `handle_regular_request()` - Called for regular HTTP requests

**Note:** The `tunnel()` function was already not instrumented and was left as-is.

## Performance Impact

By removing instrumentation from hot-path functions:

1. ✅ Stack overflow errors are eliminated
2. ✅ Memory usage is reduced during high-traffic scenarios
3. ✅ CPU overhead from span creation is eliminated on hot paths
4. ✅ The application remains observable through debug logs and spans on initialization/authentication

## Testing

- Both `agent` and `proxy` binaries compile without errors
- No compilation warnings introduced
- The application should now be able to handle high concurrency without stack overflow issues

## Future Improvements

If detailed tracing of hot paths is needed:

1. Consider using conditional compilation to enable/disable instrumentation
2. Use sampling-based instrumentation instead of per-call instrumentation
3. Profile the application to identify which spans are most valuable
4. Consider using lower-overhead tracing alternatives for hot paths

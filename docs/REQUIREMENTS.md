# Secure Proxy Application

## Background

You are an expert Rust developer, specializing in network application developing. You are developing a proxy application that consists of two main components: an agent side and a proxy side. The agent side runs on the client machine, forwarding all traffic to the proxy side, which then forwards the traffic to the target server. The proxy side also handles responses from the target server, sending them back to the agent side, which in turn forwards them back to the client machine.

## Business requirements

- Write a proxy application, it has an agent side and a proxy side. The agent side will run on the client machine, it will forward all the traffic to the proxy side, and the proxy side will forward the traffic to the target server. The proxy side will also forward the response from the target server back to the agent side, and the agent side will forward the response back to the client machine.

- The agent side should support HTTP and SOCKS5 protocols, it is no need for user to select to use HTTP or SOCKS5, the agent side should detect the protocol automatically.

- The proxy side should support multiple concurrent connections and handle errors gracefully.

- To make the DNS resolution secure, the agent side should not resolve the domain name, it should send the domain name to the proxy side, and the proxy side should resolve the domain name and connect to the target.

- It should support multiple user to use agent connect to proxy, each user should have different username and password, they should not impact each other. The authentication should be done on the agent side before forwarding the traffic to the proxy side. The bind width limit should be configurable for each user on the proxy side.

- Each user should have his own RSA key, their public key is stored in proxy side and public key is configured in agent side user configuration file.

- In agent side there should be a UI which can run in Windows and Mac OS, so that the agent user can configure the agent through UI without restart agent. The confiugraiton items should including:
  - The listning address of the agent.
  - The proxy address
  - The username
  - The UDP transport mode: native encrypted UDP or TCP/Yamux. It must be locked while the Agent is running.
  - The native UDP session count (1-8), shown only when native UDP mode is selected.
  - The UDP Yamux session count used only by TCP mode.
  - The desktop TUN UDP proxy/direct switch
  - The log level

## Architecture requirements

The communication between agent and proxy should be secure, using RSA encryption for key exchange and AES for encrypting the traffic.

The configuration for both sides should be read from a configuration file using the `config` crate, and the configuration data should be serialized/deserialized using `serde`. And configuration should be able to be overridden by command line arguments using `clap`.

The agent side should always use the original direct framed TCP connections for TCP relay. Proxied UDP should use stateful native encrypted UDP sessions when `transport_mode = "udp"`, or raw TCP/Yamux sessions when `transport_mode = "tcp"`. The native UDP session pool size should be configurable from 1 to 8, and each UDP flow should map stably to one session.

When desktop TUN `proxy_udp` is disabled, UDP other than independently handled proxy DNS and UDP/443 should leave directly from the agent's bound physical interface. Any UDP traffic selected by `direct_access`, including application-layer UDP/443 QUIC, should use a local bound/protected UDP socket and must not pass through the PPAASS native UDP encapsulation. UDP/443 remains governed by the independent application-layer `quic_policy`; blocking it forces the application to fall back to TCP/TLS.

The Proxy should listen on TCP and raw UDP on the same configured numeric port. Native UDP session establishment should authenticate the user identity with RSA and establish session key material. HKDF should derive independent Agent-to-Proxy and Proxy-to-Agent AES-256-GCM keys and nonce prefixes. Each encrypted datagram should have a per-direction monotonically increasing sequence number; protocol header fields including version, session ID, and sequence number should be authenticated as AAD. A sliding replay window should accept bounded reordering while dropping duplicate and stale packets. The outer UDP transport must not add reliable ordering or retransmission. Payloads larger than the safe datagram size should use bounded protocol fragmentation/reassembly, with every fragment authenticated independently.

The Proxy should enforce configurable limits for authenticated native UDP sessions, queued datagrams, outer flows per native UDP session, and inner target sockets per shared UDP relay. Capacity checks must happen before creating a target socket or worker. Duplicate Connect messages for an existing flow should remain idempotent when the limit is reached, and fragment reassembly must have independent per-session entry, byte, and timeout bounds without reducing the 70 KiB message limit.

The old `transport_mode = "quic"` and `quic_connection_pool_size` configuration must be rejected rather than treated as aliases or migrated automatically.

The RSA keys should be generated using a secure random number generator, and the keys should be stored securely on both sides.

The network package encoding and decoding should use the `Encoder` and `Decoder` trait form `tokio-codec` crate.

The UI of agent should use `tauri 2`, `typescript` and `vue3`, and `primevue` should be used as the component library of `vue3` .

The user management in proxy side should use the proxy users TOML configuration file to do CRUD.

## Implementation details

- Programming Language: Rust 1.93.0 with edition `2024`
- Key Libraries/Frameworks:
  - Use `tokio` as the basic network framework.
  - Use `config` as the crate to read configuration file.
  - Use `serde` for serialization and deserialization of configuration data.
  - Use `clap` for command line argument parsing.
  - Use `tracing` for logging.
  - Use `thiserror` to define errors.
  - Use `anyhow` to throw application level errors.
  - Use `tokio-codec` for network package encoding and decoding.
  - Use `fast-socks5` latest stable version to implement the socks5 protocol logic in agent side.
  - Use `hyper` latest stable version to implement the http protocol logic in agent side.
  - Use a native encrypted UDP session manager for UDP mode and a lightweight Yamux session manager for TCP-mode UDP relay.
  - All the used crates should be the latest available stable version on crates.io.
  - The version of the crates should be defined in the workspace `Cargo.toml` file.
- Important logic:
  - The configuration file format should be `TOML`.
  - The Yamux sessions from agent to proxy should be created lazily on demand; agent startup should not proactively open idle TCP/Yamux sessions. This rule does not redefine the configured native UDP session pool.
  - The project should keep the desktop agent backend in `desktop-agent-be` and the server proxy in `proxy`.
  - The common logic should be organized as a separate crate named `common` in the workspace.
  - The protocol between agent and proxy should be designed by yourself, it should be efficient and secure and organized as a separate crate named `protocol` in the workspace.
  - The codec should use `LengthDelimitedCodec` from `tokio-util` as the base codec.
  - The data package transferred between agent and proxy should use `Framed` trait so that the data can be sent and received in a stream way.
  - There should be debug logs for important steps in the application flow, especially on the time data is transferring between agent and proxy, the debug log should print the content of the data package in hex format.
  - The log level should be configurable via the configuration file and cli parameter.
  - The log should print into log files in non-blocking mode.
  - The thread number of `tokio` runtime should be configurable via the configuration file and cli parameter.
  - The agent and proxy will be deployed separately on different host, so the startup script should be separate, and should assume the final build target is in the same folder of the startup script.
  - The startup script should first stop the current running process and start a new process.
  - The agent will run in Windows and MacOS, so the startup script for agent should be a `bat` file for Windows and `sh` file for MacOS.
  - The proxy will run in Linux, so the startup script for proxy should be a `sh` file for Linux.
  - The CRUD for user in proxy side should read and write the proxy users TOML configuration file.
  - The `Data forwarding process` should use `tokio::io::copy_bidirectional` to forward data between client, agent, proxy and target.
- Flow:
  - The direct framed TCP path and TCP-mode Yamux business substreams should include 3 processes:
    - *Authentication process* to use the user's private key to authenticate a randomly generated AES key, and then send it to proxy. On proxy side, proxy should find the user's public key and recover the raw AES key so that this AES key can be used to encrypt the following traffic. This process happens once per direct framed TCP connection or Yamux substream.
    - *Connect process* to send the target server address from agent to proxy, and proxy connect to the target server. The data sent in this process should be encrypted with the AES key which exchanged in the *Authentication process*.
    - *Data forwarding process* to forward the data between client and target server via agent and proxy. The data sent in this process should be encrypted with the AES key which exchanged in the *Authentication process*. The data relay in both agent and proxy should bidirectional.
  - Native UDP mode should use the authenticated datagram session protocol described above instead of pretending a UDP datagram is an ordered Auth/Connect/Data byte stream. UDP flow identity, target metadata, payload, and bounded fragmentation metadata should be carried in authenticated datagrams.

## Mocking

- Create mock client which can support HTTP and SOCKS5 protocol use agent connect to proxy and then to target.
- Create mock target which can receive the request from client through agent and proxy.

## Testing

- Unit tests:
  - Unit tests should be written for important logic.
- Integration tests:
  - Integration tests should be written to test the whole flow.
  - Run the integration testing with mock client and mock target.
- Load tests:
  - Load tests should be written to test the performance and stability of the application.
  - Generate the performance testing report.

## Github Workflow

There should be github workflow to do build, integration testing and deploy.

- The container to run the workflow should be Debine latest stable version.
- Build workflow to build project and run the unit testing.
- Integration testing work flow, run the integration teting.
- Deploy workflow:
  - Deploy the proxy build result and related configuration files to target linux server with SCP, and start the proxy side with the `start-proxy.sh`.
  - The proxy build result should copy to the folder path with is defined in repository secrets with key `DEPLOY_FOLDER`.
  - The configuration file should be copy to the same level of the build reustl.
  - The deploy workflow should be triggered manually, with a selection of enviorment types:
    - `production`
    - `dev`
    - `qa`
  - In deploy workflow the target linux server hostname, username and password of the target linux server should read from repository secrets.
    - For `production` env:
      - The linux server ip address is defined with: `PRODUCTION_REMOTE_HOST`
      - The linux server username is defined with: `PRODUCTION_REMOTE_USER`
      - The linux server password is defined with: `PRODUCTION_REMOTE_PASSWORD`
    - For `dev` env:
      - The linux server ip address is defined with: `DEV_REMOTE_HOST`
      - The linux server username is defined with: `DEV_REMOTE_USER`
      - The linux server password is defined with: `DEV_REMOTE_PASSWORD`
    - For `qa` env:
      - The linux server ip address is defined with: `QA_REMOTE_HOST`
      - The linux server username is defined with: `QA_REMOTE_USER`
      - The linux server password is defined with: `QA_REMOTE_PASSWORD`

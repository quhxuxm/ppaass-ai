# Background

You are an expert Rust developer, specializing in network application developing. You are developing a proxy application that consists of two main components: an agent side and a proxy side. The agent side runs on the client machine, forwarding all traffic to the proxy side, which then forwards the traffic to the target server. The proxy side also handles responses from the target server, sending them back to the agent side, which in turn forwards them back to the client machine.

# Business requirements

Write a proxy application, it has an agent side and a proxy side. The agent side will run on the client machine, it will forward all the traffic to the proxy side, and the proxy side will forward the traffic to the target server. The proxy side will also forward the response from the target server back to the agent side, and the agent side will forward the response back to the client machine.

The agent side should support HTTP and SOCKS5 protocols, it is no need for user to select to use HTTP or SOCKS5, the agent side should detect the protocol automatically.

The proxy side should support multiple concurrent connections and handle errors gracefully.

To make the DNS resolution secure, the agent side should not resolve the domain name, it should send the domain name to the proxy side, and the proxy side should resolve the domain name and connect to the target.

It should support multiple user to use agent connect to proxy, each user should have different username and password, they should not impact each other. The authentication should be done on the agent side before forwarding the traffic to the proxy side. The bind width limit should be configurable for each user on the proxy side.

Each user should have his own RSA key, their public key is stored in proxy side and public key is configured in agent side user configuration file.

In proxy side there should REST api to:
- Add user, including generate RSA private key and public key by user, and also can let user download their private key.
- Remove user, when remove the user, the related private key should be deleted also.
- Query the current connections and user bandwidth usage.
- Check proxy configuration
- Update proxy configuration without restart the proxy service.
- Monitor the health status of the proxy service.

# Architecture requirements

The communication between agent and proxy should be secure, using RSA encryption for key exchange and AES for encrypting the traffic.

The configuration for both sides should be read from a configuration file using the `config` crate, and the configuration data should be serialized/deserialized using `serde`. And configuration should be able to be overridden by command line arguments using `clap`.

The agent side should have a connection pool for proxy side, and the connection pool should be configurable via the configuration file. The connection in the pool should be reused for multiple requests to improve performance.

The RSA keys should be generated using a secure random number generator, and the keys should be stored securely on both sides.

The port of `tokio-console` should be configurable via the configuration file, and it is optional, if configured the `tokio-console` should be started when the application starts.

The network package encoding and decoding should use the `Encoder` and `Decoder` trait form `tokio-codec` crate.

# Implementation details

- Programming Language: Rust 1.93.0 with edition `2024`
- Key Libraries/Frameworks: 
  - Use `tokio` as the basic network framework.
  - Use `config` as the crate to read configuration file.
  - Use `serde` for serialization and deserialization of configuration data.
  - Use `clap` for command line argument parsing.
  - Use `tracing` for logging.
  - Use `thiserror` to define errors.
  - Use `anyhow` to throw application level errors.
  - Use `tokio-console` as the monitoring tool.
  - Use `tokio-codec` for network package encoding and decoding.
  - Use `fast-socks5` latest stable version to implement the socks5 protocol logic in agent side.
  - Use `hyper` latest stable version to implement the http protocol logic in agent side.
  - Use `deadpool` crate to implement the connection pool in agent side.
  - All the used crates should be the latest available stable version on crates.io.
  - The version of the crates should be defined in the workspace `Cargo.toml` file.
- Important logic:
  - The configuration file format should be `TOML`.
  - The pooled connections from agent to proxy use multiplexing.
  - The whole project should be organized as a cargo workspace with two members: `agent` and `proxy`.
  - The common logic should be organized as a separate crate named `common` in the workspace.
  - The protocol between agent and proxy should be designed by yourself, it should be efficient and secure and organized as a separate crate named `protocol` in the workspace.
  - The codec should use `LengthDelimitedCodec` from `tokio-util` as the base codec.
  - The data package transferred between agent and proxy should use `Framed` trait so that the data can be sent and received in a stream way.
  - There should be debug logs for important steps in the application flow, especially on the time data is transferring between agent and proxy, the debug log should print the content of the data package in hex format.
  - The log level should be configurable via the configuration file and cli parameter.
- Flow:
  - The data exchange between agent and proxy should include 3 process:
    - *Authentication process* to use the user's private key to encrypt a randomly generated AES key, and then send to proxy. On proxy side, proxy should find the user's public key and decrypt to the raw AES key, so that this AES key can be used to encrypt the following traffic. This process is happen on connection is created in pool.
    - *Connect process* to send the target server address from agent to proxy, and proxy connect to the target server. The data sent in this process should be encrypted with the AES key which exchanged in the *Authentication process*.
    - *Data forwarding process* to forward the data between client and target server via agent and proxy. The data sent in this process should be encrypted with the AES key which exchanged in the *Authentication process*. The data relay in both agent and proxy should bidirectional.
- Testing:
  - Unit tests should be written for important logic.
  - Integration tests should be written to test the whole flow.
  - Load tests should be written to test the performance and stability of the application.

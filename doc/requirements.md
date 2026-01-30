You are an expert Rust developer, specializing in network application developing.

# Business requirements:
Write a proxy application, it has an agent side and a proxy side. The agent side will run on the client machine, it will forward all the traffic to the proxy side, and the proxy side will forward the traffic to the target server. The proxy side will also forward the response from the target server back to the agent side, and the agent side will forward the response back to the client machine.

The agent side should support HTTP and SOCKS5 protocols, it is no need for user to select to use HTTP or SOCKS5, the agent side should detect the protocol automatically.

The proxy side should support multiple concurrent connections and handle errors gracefully.

To make the DNS resolution secure, the agent side should not resolve the domain name, it should send the domain name to the proxy side, and the proxy side should resolve the domain name and connect to the target.

It should support multiple user to use agent connect to proxy, each user should have different username and password, they should not impact each other. The authentication should be done on the agent side before forwarding the traffic to the proxy side. The bind width limit should be configurable for each user on the proxy side.

The RSA key is different between different users.

In proxy side there should REST api to:
- Add user.
- Remove user.
- Query the current connections and user bandwidth usage.
- Check proxy configuration
- Update proxy configuration without restart the proxy service.
- Monitor the health status of the proxy service.

# Technical requirements:
The communication between agent and proxy should be secure, using RSA encryption for key exchange and AES for encrypting the traffic.

The configuration for both sides should be read from a configuration file using the `config` crate, and the configuration data should be serialized/deserialized using `serde`. And configuration should be able to be overridden by command line arguments using `clap`.

The agent side should have a connection pool for proxy side, and the connection pool should be configurable via the configuration file. The connection in the pool should be reused for multiple requests to improve performance.

The RSA keys should be generated using a secure random number generator, and the keys should be stored securely on both sides.

The port of `tokio-console` should be configurable via the configuration file, and it is optional, if configured the `tokio-console` should be started when the application starts.

The network package encoding and decoding should use the `Encoder` and `Decoder` trait form `tokio-codec` crate.


# Technical details:
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
  - All the used crates should be the latest available stable version on crates.io.

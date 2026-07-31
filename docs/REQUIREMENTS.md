# Secure Proxy Application

## Background

You are an expert Rust developer, specializing in network application development. You are developing a secure proxy platform with these main runtime components:

- Desktop and Android Agents run on client devices and forward traffic.
- `proxy-entry` is the data plane that authenticates Agents and relays TCP and UDP traffic.
- `proxy-registry` is the Axum control plane for registration, login, account management, key approval, permissions, Proxy address assignment, access history and audit records.
- The Registry frontend and Desktop Agent UI use Vue 3 and PrimeVue; the desktop shell uses Tauri 2.

The Agents forward traffic to an assigned Proxy Entry, which connects to the target and relays the response back to the originating client.

## Business requirements

- Write a proxy application with Agent, Proxy Entry and Proxy Registry components. The Agent runs on the client machine and forwards traffic through a Proxy Entry. Proxy Registry owns account registration, authentication and the configuration assigned to each Agent.

- The Agent should support HTTP and SOCKS5 clients and detect the protocol automatically.

- Proxy Entry should support multiple concurrent connections and handle errors gracefully.

- To make DNS resolution secure, the Agent should send domain names to Proxy Entry, which resolves them and connects to the target.

- It should support multiple isolated users. Users authenticate to Proxy Registry with a login name and password, while Proxy Entry authenticates data-plane connections with the RSA identity provisioned to the Agent. Per-user data-plane permissions and capacity limits must be enforced by Proxy Entry, not only hidden in the UI.

- Each user should have a versioned RSA key pair. The public key is stored in the Registry user database and consumed by Proxy Entry. The encrypted private key is released only to the authenticated owner Agent, stored in the Agent's restricted local credential directory, applied automatically, and never displayed or made editable in the UI.

- The Agent UI should run on Windows and macOS and apply supported configuration changes without requiring an Agent restart. Configurable items include:
  - The Agent listening address.
  - The UDP transport mode: automatic fallback, native encrypted UDP or TCP/Yamux. It must be locked while the Agent is running.
  - The native UDP session count (1-8), shown only when native UDP mode is selected.
  - The UDP Yamux session count used by TCP mode and by the TCP fallback path of automatic mode.
  - The desktop TUN UDP proxy/direct switch
  - The log level

  The Proxy Registry URL is read from the Agent configuration and must not be exposed on the login page. Proxy Entry addresses, the data-plane username and the managed private key are returned by Proxy Registry after authentication and must not be editable or displayed in Agent configuration pages.

## Requirements consolidated on 2026-07-29 and 2026-07-30

The requirements in this section are normative and supersede any older conflicting requirement in this document.

### Component names and persistence

- The current data-plane service, Cargo package, binary, configuration and service name are `proxy-entry`. The old `proxy` service name may appear only in explicitly marked migration/cleanup logic.
- The current account/configuration service, Cargo package, binary and service name are `proxy-registry`. The old `proxy-web` service name may appear only in explicitly marked migration/cleanup logic.
- Proxy Registry uses Axum and a Vue 3 + PrimeVue frontend.
- User CRUD must use the database-independent repository traits inside `proxy-registry::store`. SQLite is the current adapter, but handlers and domain APIs must not expose SQLite types so another database can be added later.
- `users.toml` is no longer a supported user source or compatibility path. Proxy Registry exclusively owns account, profile, encrypted-key, Proxy-address, approval, audit and access data. Proxy Entry requests public authorization snapshots through the authenticated control API and never opens SQLite.
- Proxy access records use a separate Registry-owned SQLite database. Repeated visits by the same user to the same host/address must update the last-access time and increment a counter instead of inserting an unbounded number of duplicate rows. Entry reports bounded batches identified by `(entry_id, batch_id)` so an HTTP retry cannot double count a batch.
- The current production topology runs two Proxy Registry processes on one Registry host against the same SQLite files. Caddy uses a sticky cookie for the public Web/API listener because Web sessions remain process-local, while the stateless Entry control listener is randomly balanced. Durable Agent events and one-time handoff codes use ordinary SQL so both Registry processes observe consistent state. Proxy Entry may run on a separate server; moving Registry processes to separate hosts requires replacing SQLite with a central database.

### Registration, login and account lifecycle

- Proxy Registry supports local account registration and password login only; OAuth providers are not exposed.
- Passwords must contain at least eight Unicode characters, must not exceed 256 UTF-8 bytes and are stored as Argon2id hashes. Users can change their own password after supplying the current password; a successful change invalidates their existing Web sessions.
- Browser authentication uses an opaque server-side session in an HttpOnly cookie, CSRF protection for state-changing requests, request-rate limits and non-enumerating authentication errors. There is no shared administrator token.
- The fixed root administrator is `admin`; its initial password is supplied by the deployment secret `PPAASS_WEB_ADMIN_PASSWORD`. It cannot be disabled, demoted or deleted. Other administrator and normal-user accounts can be disabled, and only disabled accounts can be deleted.
- Web-login status and Proxy-connection status are independent. An administrator must be able to disable an account even when it has no assigned Proxy address or no generated Proxy profile.
- Administrator accounts may also own a Proxy profile and keys and use the Agent. Their data-plane TCP/UDP permissions are still checked against their own profile.
- The Desktop Agent on Windows/macOS and the Android Agent must show a login gate before exposing the workspace. Agent login uses the native password API directly and must not require browser login.
- Both Desktop and Android login pages provide an explicit “remember username and password” option. Desktop stores the opted-in values in the WebView's `localStorage`, Android uses app-private `SharedPreferences`, and clearing the option removes the saved values.
- The Agent login page provides a “Register and manage account” action. Before Agent login it opens the ordinary Registry registration/login view. After Agent login it creates a 90-second, single-use, same-origin handoff and opens an already-authenticated account-management view.
- A Web session created from an Agent handoff must not show a redundant logout action. Invalid, expired, consumed or cross-origin handoff values must be rejected.
- An Agent login with intact local credentials remains established until the user explicitly logs out. Temporary Registry/Proxy network errors, HTTP 401/5xx responses and Proxy connection failures must not erase the account or managed key; malformed, corrupted or unreadable persisted credentials may require a fresh login.
- If the authoritative account/profile is disabled or its key expires, the Agent and VPN remain running, retain the logged-in identity/local credential and continue retrying. The UI shows a clear disabled/expired error, while Proxy Entry rejects unauthorized traffic during handshake or authorization recheck. The Agent must not silently return to the login screen.

### Profile and account management

- Users can update their login password, nickname and avatar from “My account”.
- A nickname is trimmed, rejects control characters and is limited to six Unicode characters.
- Avatar input supports PNG, JPEG and WebP with a maximum original size of 1 MiB. The client must scale every accepted image to exactly 64 × 64 pixels without preserving the original aspect ratio; the server validates the final dimensions.
- Avatar data is stored in the account SQLite database, not as an unmanaged server-side file.
- Nickname and avatar are returned to Desktop and Android Agents and are used wherever the logged-in account or a key applicant is displayed.
- Registry and Agent UI must not display public or private key material. Administrator APIs must not return either key, and owner Web pages must not expose private-key copy/download endpoints; managed private keys are delivered only to the authenticated native Agent.

### Key request, approval and rotation

- Registration creates an account without automatically exposing a key. A user or administrator with no key, or with an expired key, submits an initial/regeneration request and waits for administrator approval.
- A key request accepts an optional user message of at most 500 characters. Each account can have at most one pending request, and concurrent duplicate submissions must be idempotent. The administrator approval UI displays the applicant's avatar, nickname/login name, request kind, message and request time.
- Approval requires an audit reason, a strictly future expiration time and one or more enabled Proxy addresses. Approval generates the RSA pair on the server, stores the encrypted private-key envelope and atomically updates the profile, address assignments, request and audit records.
- Rejection requires an administrator-provided reason of at most 500 characters. The user can see the rejection reason, reviewer identity and review result.
- The administrator who approved or rejected a request must be persisted with the request. User-initiated and administrator-initiated key regeneration must likewise record the actual actor.
- Administrators can create an already-approved normal account with permissions, expiration and Proxy-address assignments. The server generates the key pair, but no administrator response or UI may reveal either key.
- Proxy Registry encrypts managed private keys at rest with AES-256-GCM under a deployment master key. A private key can be retrieved only through the authenticated native Agent API for its owner.
- A user with an active, unexpired key and `key.rotate` permission can regenerate a key from the Agent after password confirmation. The Agent validates the returned key pair, writes it to restricted local storage and restarts a running Agent with the new credential.
- Missing or expired keys cannot bypass approval through direct rotation or by editing the expiration time.
- Logged-in administrators can list, approve and reject pending requests directly from both Desktop and Android Agents. Pending counts use a compact badge that must not distort the sidebar or mobile navigation when the count grows.
- Approval/rejection lists and dialogs must remain usable with many requests: the list scrolls, adjacent panels retain spacing, and mobile dialogs keep fields and actions within the viewport.

### Agent permissions and Proxy assignment

- Every Web-managed profile created or approved through Proxy Registry includes the non-optional baseline capabilities below. Historical database profiles retain their explicitly migrated permission semantics until updated through a supported management flow:
  - `proxy.connect.tcp`
  - `proxy.connect.udp`
  - `key.private.read`
  - `key.rotate`
- Administrators can assign these optional Agent-management permissions to normal users:
  - `agent.packet_capture`: show and operate packet capture.
  - `agent.egress.edit`: show and edit the entire egress page.
  - `agent.runtime_threads.edit`: show and edit runtime thread settings.
- Baseline capabilities are not presented as optional checkboxes. Administrator accounts have all three Agent-management capabilities effectively enabled, although Proxy Entry still enforces their profile's baseline traffic permissions.
- When an optional permission is absent, its page or panel is not displayed and the Agent uses built-in defaults. Permission checks must also be enforced by native/Tauri commands so a hidden control cannot be bypassed.
- Permissions, role, account status, key state, nickname, avatar and assigned Proxy addresses are returned by Agent authentication and are reapplied when Registry sends a change event. UI visibility must update without restarting or logging out.
- Administrators maintain a normalized Proxy-address catalog containing a stable ID, label, address and enabled state. Catalog and account-assignment views use structured table/checklist layouts rather than free-form cards.
- Creating/editing a user or approving any initial/regeneration key request assigns one to 32 distinct enabled catalog entries using checkboxes. Approval atomically replaces the request owner's assignments. An address that is still assigned cannot be disabled, and only disabled, unreferenced entries can be deleted.
- Agent UI never displays assigned remote Proxy addresses. It receives them from Registry and uses them automatically. Legacy Agent-configured Proxy addresses are not supported.
- If an otherwise valid account has no assigned Proxy address, a new Agent login returns a stable HTTP 409 conflict and does not establish a login state. If an already signed-in Agent receives the same conflict during synchronization, it retains its identity, clears unusable assigned addresses, stops new Proxy traffic and tells the user to wait for administrator assignment.

### Access history

- Proxy Entry records a user's target access by normalized host/address. A repeated `(username, target_host)` visit increments `access_count` and updates the latest port, protocol and access time instead of inserting another row.
- Access history stores only target host/IP, latest port, TCP/UDP protocol, access count and latest access time. It must not store an HTTPS URL path or page contents.
- Normal users can view only their own retained records. Administrators can configure the global retention window from one to 365 days; it defaults to seven days, and records older than the active window are purged.
- The “Recent access” table supports host filtering, sortable columns and pagination without exposing another user's detailed history to an administrator.

### Real-time Agent synchronization

- Successful native Agent login returns the account, role, profile, permissions, Proxy addresses, profile identity, managed private key and a renewable Agent access token in one response.
- Desktop and Android Agents maintain a Server-Sent Events connection to `/api/v1/agent/events` after login. Agent business state must not be refreshed by continuous fixed-interval polling.
- The event stream sends an initial `sync` event and supports targeted/global invalidation events for profile, Proxy-address and key-request changes. A 15-second keep-alive is used for idle connections; a lagged subscriber receives a replacement `sync` event.
- On an event, the Agent fetches the latest authoritative profile and refreshes both UI permissions and native runtime constraints. An administrator also refreshes the pending-request list.
- SSE reconnect uses bounded exponential backoff from one to 60 seconds. The server closes each stream after 12 hours so the Agent reconnects and refreshes expiring authentication state. A disconnected stream or temporary synchronization failure keeps the last successfully verified configuration and presents a synchronization error.
- Agent access tokens are encrypted/authenticated with a deployment secret, survive Registry process restarts and are never exposed to frontend JavaScript or logs.

### Administrator audit

- Only administrators can view operation-audit records.
- Audit events cover:
  - key-request approval and rejection;
  - user- or administrator-initiated key regeneration;
  - enabling/disabling Proxy access;
  - enabling/disabling Web login;
  - enabling/disabling a Proxy-address catalog node;
  - assigning or changing user permissions.
- Every administrator-triggered audited mutation requires a trimmed reason from one to 500 characters. The audit row records action, actor account/login snapshot, target kind/ID/name, related request ID where applicable, reason, previous value, new value and timestamp. Reviewer and disabling-administrator login snapshots remain readable after either account is later deleted. A user's own direct key rotation is also audited with that user as actor, but its reason may be empty.
- Audit insertion must be in the same repository transaction as the sensitive business mutation so the operation and its audit record cannot diverge.
- The audit UI provides server-side filtering by action and free-text search across actor, target, reason and request/context ID. Search text is limited to 120 characters, page size is limited to one through 500 records, and results use stable `before_audit_id` cursor pagination, a responsive scrollable table and an explicit “load earlier records” action.

### Network, TUN and packet-capture behavior

- TCP/Yamux authentication uses protocol version 3. Unknown users, stale timestamps, invalid signatures and replayed requests receive the same unsigned generic failure. Only after the Agent proves possession of the current private key with a fresh, non-replayed request may Proxy Entry return a Proxy-identity-signed `UserDisabled` or `UserExpired` terminal status.
- Retryable network failures must remain distinct from authoritative account-disabled, profile-disabled, key-expired and permission-denied failures.
- Proxy Entry enforces a configurable per-username limit for concurrently authenticated native UDP sessions in addition to global capacity limits. The per-username default is 64 and the effective value is capped by the global session limit.
- Established TCP/Yamux relays and native UDP sessions recheck account/profile status, the relevant TCP/UDP permission, key version and absolute expiration at least once every five seconds. Revocation, disablement, key rotation or expiration must terminate affected traffic within that bound; a shared TCP/Yamux UDP relay also rechecks before creating a new flow.
- On macOS, TUN route and DNS capture changes must be bound to the selected physical gateway/interface, preserve bypass routes for Registry and assigned Proxy endpoints, and restore system routes/DNS on shutdown. Helper replacement must be version-safe and must not damage an already working installed helper during ordinary UI testing.
- Selecting DNS records that have no existing direct rule must create normalized `direct_access` rules and enable the “add and restart” action.
- Packet capture is available only with `agent.packet_capture`. Plaintext capture configuration and results live on the packet-capture page.
- The capture page must keep its own scrollable workspace, use compact packet/upload/download/file-size metrics, display zero bytes as `0 字节` rather than ambiguous `0B`, and provide filterable/sortable packet tables without large empty panels.

### UI, testing and delivery

- Registry user lists, audit tables, Proxy catalogs and edit dialogs must support large datasets with pagination or scrolling. Long usernames, permission collections and Proxy labels must use bounded columns, ellipsis/summary display and full-value titles instead of wrapping the entire row.
- The user table shows the role without a redundant source label, Web-login status as a green/gray dot and “Key expiration” as the expiration heading; expired values are highlighted in red. Long usernames, assigned-node names and permission summaries stay on one line and expose their full values through a title/tooltip.
- Registry desktop and mobile top bars must keep “My account”, administrator user management and logout reachable without overlap or clipping.
- The Desktop Agent keeps the signed-in profile beneath the sidebar navigation without allowing a long name to resize the sidebar. The egress page must not contain a credential/private-key editor because those values are Registry-managed.
- Proxy-expiration and Proxy-access controls in user dialogs use aligned control heights. Administrator profiles show all Agent permissions as checked and read-only rather than a synthetic “Agent full permissions” label or `0/3` counter.
- Android authentication/admin JSON uses typed DTO/POJO models and Jackson parsing rather than ad-hoc string extraction.
- Desktop behavior on Windows/macOS and Android behavior must remain functionally aligned, and Android changes must be exercised on an emulator. Android release scripts must always produce `app-release-signed.apk`: use configured signing credentials when supplied, otherwise create and reuse the gitignored local release keystore.
- Performance tooling generates JSON, Markdown and HTML reports for applicable general, TCP, UDP, QUIC and large-download scenarios. Reports include throughput, P50/P95/P99 latency, CPU, memory and cross-report summaries/comparisons, and report generation has automated tests.
- Frontend tests run before deployment, and the deployed Registry frontend exposes a version marker matching the deployed commit.
- Linux start scripts provide start/stop/status supervision, PID handling, log setup, configuration validation and health checks for `proxy-entry` and `proxy-registry`. Windows also has a `start-proxy-entry.bat` helper.
- Production deployment builds and deploys both renamed services. Proxy Registry listens on `127.0.0.1:8787` and is exposed through Caddy on HTTPS/443 with automatic certificate renewal, while Proxy Entry retains its configured TCP/raw-UDP data-plane port.
- CI must reject any tracked or unignored Rust, TypeScript, Vue, JavaScript, HTML, CSS, shell, YAML, PowerShell or batch source/configuration file longer than 400 lines. Large features must be split into focused modules/components.

## Architecture requirements

The communication between Agent and Proxy Entry should be secure, using RSA for authenticated key exchange and AES-GCM for traffic encryption.

Runtime configuration should be read with the `config` crate and serialized/deserialized with `serde`. Supported values can be overridden by command-line arguments parsed with `clap`.

The Agent should use direct framed TCP connections for TCP relay. Proxied UDP should use stateful native encrypted UDP sessions when `transport_mode = "udp"`, raw TCP/Yamux sessions when `transport_mode = "tcp"`, or per-session-slot native UDP with TCP/Yamux fallback after native control/authentication timeout when `transport_mode = "auto"`. The native UDP session pool size should be configurable from one to eight, and each UDP flow should map stably to one session.

When desktop TUN `proxy_udp` is disabled, UDP other than independently handled proxy DNS and UDP/443 should leave directly from the agent's bound physical interface. Any UDP traffic selected by `direct_access`, including application-layer UDP/443 QUIC, should use a local bound/protected UDP socket and must not pass through the PPAASS native UDP encapsulation. UDP/443 remains governed by the independent application-layer `quic_policy`; blocking it forces the application to fall back to TCP/TLS.

Proxy Entry should listen on TCP and raw UDP on the same configured numeric port. Native UDP session establishment should authenticate the user identity with RSA and establish session key material. HKDF should derive independent Agent-to-Proxy Entry and Proxy Entry-to-Agent AES-256-GCM keys and nonce prefixes. Each encrypted datagram should have a per-direction monotonically increasing sequence number; protocol header fields including version, session ID and sequence number should be authenticated as AAD. A sliding replay window should accept bounded reordering while dropping duplicate and stale packets. The outer UDP transport must not add reliable ordering or retransmission. Payloads larger than the safe datagram size should use bounded protocol fragmentation/reassembly, with every fragment authenticated independently.

Proxy Entry should enforce configurable global and per-username limits for authenticated native UDP sessions, queued datagrams, outer flows per native UDP session and inner target sockets per shared UDP relay. Capacity checks must happen before creating a target socket or worker. Duplicate Connect messages for an existing flow should remain idempotent when the limit is reached, and fragment reassembly must have independent per-session entry, byte and timeout bounds without reducing the 70 KiB message limit.

The old `transport_mode = "quic"` and `quic_connection_pool_size` configuration must be rejected rather than treated as aliases or migrated automatically.

The RSA keys should be generated using a secure random number generator, and the keys should be stored securely on both sides.

Network package encoding and decoding should use the `Encoder` and `Decoder` traits from `tokio-util::codec`.

The Desktop Agent UI should use Tauri 2, TypeScript, Vue 3 and PrimeVue.

Proxy Registry owns user CRUD through its database-independent repository traits. SQLite is the current persistence adapter; `users.toml` is not supported.

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
  - Use `tokio-util::codec` for network package encoding and decoding.
  - Use `fast-socks5` to implement SOCKS5 protocol logic in the Agent.
  - Use `hyper` to implement HTTP protocol logic in the Agent.
  - Use a native encrypted UDP session manager for UDP/auto modes and a lightweight Yamux session manager for TCP-mode and automatic-fallback UDP relay.
  - Dependencies should be managed centrally in the workspace `Cargo.toml`; compatibility or security constraints may require an intentionally pinned version.
  - The version of the crates should be defined in the workspace `Cargo.toml` file.
- Important logic:
  - The configuration file format should be `TOML`.
  - Yamux sessions from Agent to Proxy Entry should be created lazily on demand; Agent startup should not proactively open idle TCP/Yamux sessions. This rule does not redefine the configured native UDP session pool.
  - The project should keep the desktop Agent backend in `desktop-agent-be`, the data-plane server in `proxy-entry`, the control plane and persistence contracts in `proxy-registry`, and the versioned Entry control contract in `proxy-control-protocol`.
  - Common logic should be organized as a separate workspace crate named `common`.
  - The efficient and secure Agent-to-Proxy Entry protocol should be organized as a separate workspace crate named `protocol`.
  - The codec should use `LengthDelimitedCodec` from `tokio-util` as the base codec.
  - Stream messages transferred between Agent and Proxy Entry should use `Framed`.
  - Important application steps should emit `tracing` diagnostics. Debug logging for data transfer may include bounded hexadecimal packet diagnostics, but must not expose credentials, private keys, tokens or decrypted user payloads.
  - Log level should be configurable through configuration and command-line arguments.
  - File logging should be non-blocking.
  - The Tokio runtime thread count should be configurable through configuration and command-line arguments where the signed-in user has permission to change runtime parameters.
  - Agents, Proxy Entry and Proxy Registry are independently built processes with separate startup scripts and configurations. The current production topology runs Entry independently and places two Registry processes behind Caddy on the Registry host. Both Registry processes share the local SQLite files; cross-host Registry deployment requires a central database.
  - A restart action in a startup script should stop the currently running process before starting the replacement.
  - The Agent runs on Windows and macOS, so platform helpers should be provided where packaging does not already own process startup.
  - Proxy Entry and Proxy Registry run on Linux, so each service should have its own `sh` startup script.
  - User CRUD must go through `proxy-registry::store` repository traits. Proxy Registry has exclusive ownership of user and access databases; Proxy Entry must use the authenticated control API and must not open either database.
  - The TCP data-forwarding path should use `tokio::io::copy_bidirectional` to relay data between client, Agent, Proxy Entry and target.
- Flow:
  - The direct framed TCP path and TCP-mode Yamux business substreams should include 3 processes:
    - *Authentication process*: Agent signs a domain-separated transcript containing the protocol version, username, timestamp and client nonce with RSA-PSS-SHA256. Proxy Entry verifies freshness, replay protection and the user's signature, then generates the master secret, server nonce and session ID. It encrypts that session envelope to the user with labelled RSA-OAEP-SHA256 and signs the canonical response with the pinned Proxy transport identity. After verification/decryption, both sides derive independent per-direction AEAD record keys.
    - *Connect process*: Agent sends the target address through the authenticated encrypted record layer, and Proxy Entry connects to the target.
    - *Data forwarding process*: Agent and Proxy Entry relay data bidirectionally through the authenticated encrypted record layer.
  - Native UDP mode should use the authenticated datagram session protocol described above instead of pretending a UDP datagram is an ordered Auth/Connect/Data byte stream. UDP flow identity, target metadata, payload, and bounded fragmentation metadata should be carried in authenticated datagrams.

## Mocking

- Create a mock client that exercises HTTP and SOCKS5 traffic through Agent and Proxy Entry.
- Create a mock target that receives requests relayed through Agent and Proxy Entry.

## Testing

- Unit tests:
  - Unit tests should be written for important logic.
- Integration tests:
  - Integration tests should be written to test the whole flow.
  - Run the integration testing with mock client and mock target.
- Load tests:
  - Load tests should be written to test the performance and stability of the application.
  - Generate the performance testing report.

## GitHub Workflow

GitHub Actions workflows should build, test and deploy the platform.

- The container to run the workflow should use the latest stable Debian release.
- The build workflow builds the project and runs unit tests.
- The integration workflow runs end-to-end integration tests.
- Deploy workflows:
  - Deploy Proxy Entry and Proxy Registry independently so they may run on different Linux servers.
  - Deploy two Registry processes behind Caddy; deploy Entry without SQLite or Caddy.
  - Use separate `<ENV>_ENTRY_REMOTE_*` and `<ENV>_REGISTRY_REMOTE_*` SSH credentials.
  - Read the root administrator password from the repository secret `PPAASS_WEB_ADMIN_PASSWORD`; never commit the password or generated runtime secrets.
  - Validate/install or upgrade Caddy when needed, proxy HTTPS/443 to the Registry loopback listener and preserve automatic renewal. For the current public-IP deployment, use an ACME short-lived IP certificate with TLS-ALPN-01 on 443 so renewal does not require port 80.
  - The deployment workflow should be triggered manually with an environment selector:
    - `production`
    - `dev`
    - `qa`
  - Target Linux server hostname, username and password are read from role-specific repository secrets:
    - For `production` env:
      - `PRODUCTION_ENTRY_REMOTE_HOST/USER/PASSWORD`
      - `PRODUCTION_REGISTRY_REMOTE_HOST/USER/PASSWORD`
    - For `dev` env:
      - `DEV_ENTRY_REMOTE_HOST/USER/PASSWORD`
      - `DEV_REGISTRY_REMOTE_HOST/USER/PASSWORD`
    - For `qa` env:
      - `QA_ENTRY_REMOTE_HOST/USER/PASSWORD`
      - `QA_REGISTRY_REMOTE_HOST/USER/PASSWORD`

# Build Scripts

## Build All
build-all:
	cargo build --release --workspace

## Build Individual Components
build-agent:
	cargo build --release -p agent

build-proxy:
	cargo build --release -p proxy

## Run Components
run-agent:
	cargo run --release -p agent -- --config config/agent.toml

run-proxy:
	cargo run --release -p proxy -- --config config/proxy.toml

## Development
dev-agent:
	RUST_LOG=debug cargo run -p agent -- --config config/agent.toml

dev-proxy:
	RUST_LOG=debug cargo run -p proxy -- --config config/proxy.toml

## Testing
test:
	cargo test --workspace

## Code Quality
fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace -- -D warnings

check:
	cargo check --workspace

## Clean
clean:
	cargo clean
	rm -rf keys/*.pem

## Setup
setup:
	mkdir -p config keys
	cp config/agent.toml.example config/agent.toml || true
	cp config/proxy.toml.example config/proxy.toml || true

.PHONY: build-all build-agent build-proxy run-agent run-proxy dev-agent dev-proxy test fmt clippy check clean setup

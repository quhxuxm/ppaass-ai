# Build Scripts

## Build All
build-all:
	cargo build --release --workspace

## Build Individual Components
build-agent:
	cargo build --release -p desktop-agent-be

build-proxy-entry:
	cargo build --release -p proxy-entry

## Run Components
run-agent:
	cargo run --release -p desktop-agent-be --bin desktop-agent -- --config config/agent.toml

run-proxy-entry:
	cargo run --release -p proxy-entry -- --config config/proxy-entry.toml

## Development
dev-agent:
	RUST_LOG=debug cargo run -p desktop-agent-be --bin desktop-agent -- --config config/agent.toml

dev-proxy-entry:
	RUST_LOG=debug cargo run -p proxy-entry -- --config config/proxy-entry.toml

## Testing
test:
	cargo test --workspace

test-integration:
	./run-tests.sh integration

test-performance:
	./run-tests.sh performance

test-all:
	./run-tests.sh all

mock-target:
	./run-tests.sh mock-target

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
	test -f config/agent.toml
	test -f config/proxy-entry.toml

.PHONY: build-all build-agent build-proxy-entry run-agent run-proxy-entry dev-agent dev-proxy-entry test fmt clippy check clean setup

#!/bin/bash

# PPAASS Integration and Performance Test Runner
# This script helps run the integration and performance tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "PPAASS Integration and Performance Tests"
echo "=========================================="

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo is not installed${NC}"
    exit 1
fi

# Build the integration tests
echo -e "${YELLOW}Building integration test suite...${NC}"
cargo build --release -p integration-tests
echo -e "${GREEN}✓ Build complete${NC}"

# Parse command line arguments
MODE="${1:-help}"
CONCURRENCY="${2:-100}"
DURATION="${3:-60}"
AGENT_ADDR="${AGENT_ADDR:-127.0.0.1:7070}"
PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:8080}"

case "$MODE" in
    mock-target)
        echo -e "${YELLOW}Starting mock target servers...${NC}"
        echo "HTTP server will be on port 9090"
        echo "TCP echo server will be on port 9091"
        echo "Press Ctrl+C to stop"
        cargo run --release -p integration-tests -- mock-target
        ;;
    
    integration)
        echo -e "${YELLOW}Running integration tests...${NC}"
        echo "Agent: $AGENT_ADDR"
        echo "Proxy: $PROXY_ADDR"
        echo ""
        echo "Make sure the following are running:"
        echo "  1. Agent server on $AGENT_ADDR"
        echo "  2. Proxy server on $PROXY_ADDR"
        echo "  3. Mock target servers (run: $0 mock-target)"
        echo ""
        read -p "Press Enter to continue or Ctrl+C to cancel..."
        cargo run --release -p integration-tests -- integration \
            --agent-addr "$AGENT_ADDR" \
            --proxy-addr "$PROXY_ADDR"
        ;;
    
    performance)
        echo -e "${YELLOW}Running performance tests...${NC}"
        echo "Agent: $AGENT_ADDR"
        echo "Proxy: $PROXY_ADDR"
        echo "Concurrency: $CONCURRENCY"
        echo "Duration: ${DURATION}s"
        echo ""
        echo "Make sure the following are running:"
        echo "  1. Agent server on $AGENT_ADDR"
        echo "  2. Proxy server on $PROXY_ADDR"
        echo "  3. Mock target servers (run: $0 mock-target)"
        echo ""
        read -p "Press Enter to continue or Ctrl+C to cancel..."
        
        OUTPUT_FILE="performance-report-$(date +%Y%m%d-%H%M%S).html"
        cargo run --release -p integration-tests -- performance \
            --agent-addr "$AGENT_ADDR" \
            --proxy-addr "$PROXY_ADDR" \
            --concurrency "$CONCURRENCY" \
            --duration "$DURATION" \
            --output "$OUTPUT_FILE"
        
        echo -e "${GREEN}✓ Performance test complete${NC}"
        echo "Reports generated:"
        echo "  - ${OUTPUT_FILE}"
        echo "  - ${OUTPUT_FILE%.html}.json"
        echo "  - ${OUTPUT_FILE%.html}.md"
        ;;
    
    all)
        echo -e "${YELLOW}Running all tests...${NC}"
        echo ""
        echo "This will run:"
        echo "  1. Integration tests"
        echo "  2. Performance tests (concurrency=$CONCURRENCY, duration=${DURATION}s)"
        echo ""
        echo "Make sure the following are running:"
        echo "  1. Agent server on $AGENT_ADDR"
        echo "  2. Proxy server on $PROXY_ADDR"
        echo "  3. Mock target servers (run: $0 mock-target)"
        echo ""
        read -p "Press Enter to continue or Ctrl+C to cancel..."
        
        # Run integration tests
        echo -e "${YELLOW}Step 1/2: Integration tests${NC}"
        cargo run --release -p integration-tests -- integration \
            --agent-addr "$AGENT_ADDR" \
            --proxy-addr "$PROXY_ADDR"
        
        echo ""
        echo -e "${GREEN}✓ Integration tests complete${NC}"
        echo ""
        
        # Run performance tests
        echo -e "${YELLOW}Step 2/2: Performance tests${NC}"
        OUTPUT_FILE="performance-report-$(date +%Y%m%d-%H%M%S).html"
        cargo run --release -p integration-tests -- performance \
            --agent-addr "$AGENT_ADDR" \
            --proxy-addr "$PROXY_ADDR" \
            --concurrency "$CONCURRENCY" \
            --duration "$DURATION" \
            --output "$OUTPUT_FILE"
        
        echo ""
        echo -e "${GREEN}✓ All tests complete${NC}"
        echo "Performance reports generated:"
        echo "  - ${OUTPUT_FILE}"
        echo "  - ${OUTPUT_FILE%.html}.json"
        echo "  - ${OUTPUT_FILE%.html}.md"
        ;;
    
    help|*)
        echo "Usage: $0 <mode> [options]"
        echo ""
        echo "Modes:"
        echo "  mock-target          Start mock target servers (HTTP on 9090, TCP on 9091)"
        echo "  integration          Run integration tests"
        echo "  performance [c] [d]  Run performance tests with [c]=concurrency, [d]=duration"
        echo "  all [c] [d]          Run all tests"
        echo "  help                 Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  AGENT_ADDR           Agent server address (default: 127.0.0.1:7070)"
        echo "  PROXY_ADDR           Proxy server address (default: 127.0.0.1:8080)"
        echo ""
        echo "Examples:"
        echo "  $0 mock-target"
        echo "  $0 integration"
        echo "  $0 performance 200 120"
        echo "  $0 all 100 60"
        echo "  AGENT_ADDR=10.0.0.1:7070 $0 integration"
        ;;
esac

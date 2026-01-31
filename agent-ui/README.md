# PPAASS Agent UI

Desktop UI for configuring and controlling the PPAASS Agent.

## Prerequisites

- Node.js 18+
- Rust 1.93+
- npm or pnpm

## Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run in development mode:
   ```bash
   npm run tauri dev
   ```

## Building

Build for production:
```bash
npm run tauri build
```

The built application will be in `src-tauri/target/release/bundle/`.

## Features

- Configure agent listening address
- Set proxy server address
- Manage username and authentication
- Adjust connection pool size
- Change log level dynamically
- Start/stop agent
- View real-time status and statistics

# PPAASS API Documentation

## Base URL

```
http://localhost:8081
```

## Authentication

Currently, the API endpoints do not require authentication. In a production environment, you should add authentication middleware.

## Endpoints

### Health Check

Check if the proxy service is running.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

**Example:**
```bash
curl http://localhost:8081/health
```

---

### Add User

Create a new user with RSA keys and optional bandwidth limits.

**Endpoint:** `POST /api/users`

**Request Body:**
```json
{
  "username": "string",
  "bandwidth_limit_mbps": number (optional)
}
```

**Response:**
```json
{
  "success": true,
  "message": "User myuser added successfully",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "bandwidth_limit_mbps": 100
  }'
```

**Notes:**
- Save the `private_key` immediately - it cannot be retrieved later
- The private key is also saved to `keys/{username}.pem` on the proxy server
- The public key is automatically added to the user configuration

---

### Remove User

Delete a user and their associated keys.

**Endpoint:** `DELETE /api/users`

**Request Body:**
```json
{
  "username": "string"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User alice removed successfully"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'
```

**Notes:**
- Removes the user from configuration
- Deletes the private key file from the server
- Active connections for this user will be terminated

---

### List Users

Get a list of all registered users.

**Endpoint:** `GET /api/users`

**Response:**
```json
{
  "users": ["alice", "bob", "charlie"]
}
```

**Example:**
```bash
curl http://localhost:8081/api/users
```

---

### Get Bandwidth Statistics

Get current bandwidth usage for all users.

**Endpoint:** `GET /api/stats/bandwidth`

**Response:**
```json
{
  "stats": [
    {
      "username": "alice",
      "bytes_sent": 1048576,
      "bytes_received": 2097152
    },
    {
      "username": "bob",
      "bytes_sent": 524288,
      "bytes_received": 1048576
    }
  ]
}
```

**Example:**
```bash
curl http://localhost:8081/api/stats/bandwidth
```

**Notes:**
- Counters reset every second for rate limiting purposes
- Values are in bytes

---

### Get Configuration

Retrieve the current proxy configuration.

**Endpoint:** `GET /api/config`

**Response:**
```json
{
  "listen_addr": "0.0.0.0:8080",
  "api_addr": "0.0.0.0:8081",
  "users_config_path": "config/users.toml",
  "keys_dir": "keys",
  "console_port": null
}
```

**Example:**
```bash
curl http://localhost:8081/api/config
```

---

### Update Configuration

Update proxy configuration without restarting.

**Endpoint:** `PUT /api/config`

**Request Body:**
```json
{
  "listen_addr": "0.0.0.0:8080",
  "api_addr": "0.0.0.0:8081",
  "users_config_path": "config/users.toml",
  "keys_dir": "keys"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated (not implemented)"
}
```

**Example:**
```bash
curl -X PUT http://localhost:8081/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "listen_addr": "0.0.0.0:8080",
    "api_addr": "0.0.0.0:8081",
    "users_config_path": "config/users.toml",
    "keys_dir": "keys"
  }'
```

**Note:** This endpoint is currently a placeholder. Full implementation requires hot-reload functionality.

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "success": false,
  "message": "Error description"
}
```

Common HTTP status codes:
- `200 OK`: Request successful
- `400 Bad Request`: Invalid request body
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

---

## Rate Limiting

Currently, no rate limiting is implemented. In production, consider adding:
- Request rate limits per IP
- API key authentication
- CORS configuration

---

## Security Considerations

1. **Use HTTPS**: Put the API behind a reverse proxy with TLS
2. **Add Authentication**: Implement API key or JWT authentication
3. **Restrict Access**: Use firewall rules to limit API access
4. **Audit Logs**: Log all API operations for security auditing
5. **Input Validation**: All inputs are validated, but additional checks may be needed

---

## WebSocket Support

Future versions may include WebSocket support for real-time monitoring:
- Live connection status
- Real-time bandwidth usage
- Event notifications

---

## Examples

### Complete Workflow

```bash
# 1. Check proxy is running
curl http://localhost:8081/health

# 2. Add a new user
RESPONSE=$(curl -s -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "bandwidth_limit_mbps": 50}')

# 3. Extract and save private key
echo "$RESPONSE" | jq -r '.private_key' > keys/testuser.pem

# 4. Verify user was created
curl http://localhost:8081/api/users

# 5. Monitor bandwidth
watch -n 1 'curl -s http://localhost:8081/api/stats/bandwidth | jq'

# 6. Remove user when done
curl -X DELETE http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

### Batch User Creation

```bash
# Create multiple users
for i in {1..5}; do
  curl -X POST http://localhost:8081/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"user$i\", \"bandwidth_limit_mbps\": 100}"
  sleep 1
done
```

---

## Client Libraries

You can easily create client libraries for the API:

### Python Example

```python
import requests

class PpaassClient:
    def __init__(self, base_url="http://localhost:8081"):
        self.base_url = base_url
    
    def health(self):
        return requests.get(f"{self.base_url}/health").json()
    
    def add_user(self, username, bandwidth_limit_mbps=None):
        data = {"username": username}
        if bandwidth_limit_mbps:
            data["bandwidth_limit_mbps"] = bandwidth_limit_mbps
        return requests.post(f"{self.base_url}/api/users", json=data).json()
    
    def list_users(self):
        return requests.get(f"{self.base_url}/api/users").json()
    
    def get_bandwidth_stats(self):
        return requests.get(f"{self.base_url}/api/stats/bandwidth").json()
```

---

For more information, see the main README.md and SETUP.md files.

# stargazers-log

Minimal Node backend for an iPhone control agent.

## What it does

This service accepts safe, allow-listed action requests for a registered iPhone device, queues them for pickup by an iPhone client, and records execution results.

Supported actions:
- `open_app`
- `open_url`
- `send_text`
- `run_shortcut`

Privacy tracker features:
- flag likely supercookies and cross-site tracking cookies
- trace suspicious origins back to the reporting app or domain
- recommend and store domain/app blocks per device

## API flow

1. Register a device with `POST /api/devices/register`
2. Submit a prompt or explicit actions to `POST /api/agent/commands`
3. Let the iPhone client poll `GET /api/devices/:deviceId/commands/next`
4. Send execution results to `POST /api/devices/:deviceId/commands/:commandId/result`
5. Read status from `GET /api/agent/commands/:commandId`

Privacy flow:

1. Submit device observations to `POST /api/privacy/reports`
2. Review findings and traced origins from the response
3. Let the backend auto-block recommendations or submit manual blocks to `POST /api/privacy/devices/:deviceId/block`
4. Read current privacy status from `GET /api/privacy/devices/:deviceId/status`

## Run

```bash
npm install
npm start
```

Optional environment variables:
- `PORT`: server port, defaults to `3000`
- `AGENT_API_TOKEN`: token required in the `x-agent-token` header on every `/api/*` request when set

## Example requests

Register a device:

```bash
curl -X POST http://localhost:3000/api/devices/register \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{"deviceId":"iphone-1","name":"Primary iPhone"}'
```

Queue a natural-language prompt:

```bash
curl -X POST http://localhost:3000/api/agent/commands \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{"deviceId":"iphone-1","prompt":"open safari"}'
```

Queue explicit actions:

```bash
curl -X POST http://localhost:3000/api/agent/commands \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{"deviceId":"iphone-1","actions":[{"type":"open_url","params":{"url":"https://apple.com"}}]}'
```

Submit a privacy report:

```bash
curl -X POST http://localhost:3000/api/privacy/reports \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "deviceId":"iphone-1",
    "autoBlock":true,
    "observations":[
      {
        "kind":"cookie",
        "name":"ever-id",
        "domain":".tracker.example",
        "maxAgeDays":730,
        "sameSite":"none",
        "partitioned":false,
        "sourceApp":"Safari"
      },
      {
        "kind":"app",
        "name":"Coupons+",
        "bundleId":"com.example.coupons",
        "domains":["ads.example","metrics.example","sync.example"],
        "permissions":["tracking"]
      }
    ]
  }'
```

## Shortcut/App integration example

On iPhone, a Shortcut or app can:

1. collect domains, cookies, or app metadata from its own permitted context
2. `POST` the observations to `/api/privacy/reports`
3. inspect the returned `blockedRecommendations`
4. send selected blocks to `/api/privacy/devices/:deviceId/block`

Example payload shape for an iPhone client:

```json
{
  "deviceId": "iphone-1",
  "observations": [
    {
      "kind": "cookie",
      "name": "ever-id",
      "domain": ".tracker.example",
      "maxAgeDays": 730,
      "sameSite": "none",
      "partitioned": false,
      "sourceApp": "Safari"
    },
    {
      "kind": "app",
      "name": "Coupons+",
      "bundleId": "com.example.coupons",
      "domains": ["ads.example", "metrics.example", "sync.example"],
      "permissions": ["tracking"]
    }
  ]
}
```

## Test

```bash
npm test
```

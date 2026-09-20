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
- inspect sniffed traffic summaries across WiFi, cellular, Bluetooth, and AirDrop
- queue new connections for allow/deny review with optional saved decisions
- flag sensitive egress such as calendar data leaving the device
- serve a simple built-in dashboard for reviewing findings and blocklists

## API flow

1. Register a device with `POST /api/devices/register`
2. Submit a prompt or explicit actions to `POST /api/agent/commands`
3. Let the iPhone client poll `GET /api/devices/:deviceId/commands/next`
4. Send execution results to `POST /api/devices/:deviceId/commands/:commandId/result`
5. Read status from `GET /api/agent/commands/:commandId`

Privacy flow:

1. Submit device observations to `POST /api/privacy/reports`
2. Submit sniff captures to `POST /api/privacy/sniff`
3. Submit connection events to `POST /api/privacy/connections`
4. Review pending allow/deny prompts from `GET /api/privacy/devices/:deviceId/review`
5. Save manual decisions with `POST /api/privacy/devices/:deviceId/review/:eventId`
6. Export the active blocklist from `GET /api/privacy/devices/:deviceId/block`
7. Read current privacy status from `GET /api/privacy/devices/:deviceId/status`

## Run

```bash
npm install
npm start
```

Optional environment variables:
- `PORT`: server port, defaults to `3000`
- `AGENT_API_TOKEN`: token required in the `x-agent-token` header on every `/api/*` request when set

## User interface

Open `http://localhost:3000/` for a simple dashboard that can:
- fetch device privacy status
- fetch the exported blocklist
- submit sniff capture JSON for analysis
- submit connection events for review

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

Submit sniff captures:

```bash
curl -X POST http://localhost:3000/api/privacy/sniff \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "deviceId":"iphone-1",
    "autoBlock":true,
    "captures":[
      {
        "channel":"wifi",
        "remoteHost":"ads.example",
        "protocol":"https",
        "appName":"Safari",
        "packetCount":12,
        "bytes":4096
      },
      {
        "channel":"bluetooth",
        "advertiserId":"beacon-123",
        "appBundleId":"com.example.coupons",
        "appName":"Coupons+"
      }
    ]
  }'
```

Submit a connection event for review:

```bash
curl -X POST http://localhost:3000/api/privacy/connections \
  -H 'x-agent-token: your-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "deviceId":"iphone-1",
    "connection":{
      "transport":"wifi",
      "remoteHost":"calendar-sync.example",
      "appName":"Calendar",
      "service":"caldav",
      "dataTypes":["calendar"],
      "direction":"outbound"
    }
  }'
```

Export the current device blocklist:

```bash
curl http://localhost:3000/api/privacy/devices/iphone-1/block \
  -H 'x-agent-token: your-token'
```

## iPhone client contract

Minimum client flow:

1. register the device once with `deviceId` and optional `name`
2. poll for queued commands from `GET /api/devices/:deviceId/commands/next`
3. post command execution results to `POST /api/devices/:deviceId/commands/:commandId/result`
4. post privacy observations to `POST /api/privacy/reports`
5. fetch the enforceable blocklist from `GET /api/privacy/devices/:deviceId/block`
6. optionally post sniff captures to `POST /api/privacy/sniff`
7. optionally post connection events to `POST /api/privacy/connections`

Core request and response shapes:

### Register device

Request:

```json
{
  "deviceId": "iphone-1",
  "name": "Primary iPhone"
}
```

Response:

```json
{
  "deviceId": "iphone-1",
  "name": "Primary iPhone",
  "updatedAt": "2026-09-20T00:00:00.000Z"
}
```

### Poll next command

Response:

```json
{
  "command": {
    "id": "uuid",
    "type": "open_app",
    "params": {
      "appName": "safari"
    },
    "status": "dispatched",
    "createdAt": "2026-09-20T00:00:00.000Z",
    "dispatchedAt": "2026-09-20T00:00:02.000Z"
  }
}
```

### Report command result

Request:

```json
{
  "status": "completed",
  "result": "Safari opened."
}
```

### Export blocklist

Response:

```json
{
  "deviceId": "iphone-1",
  "exportedAt": "2026-09-20T00:00:10.000Z",
  "blockCount": 2,
  "blocked": [
    {
      "type": "domain",
      "target": ".tracker.example",
      "reason": "Cookie remains valid for a year or longer.",
      "createdAt": "2026-09-20T00:00:05.000Z"
    },
    {
      "type": "app",
      "target": "com.example.coupons",
      "reason": "App requests permissions commonly used for tracking or profiling.",
      "createdAt": "2026-09-20T00:00:05.000Z"
    }
  ]
}
```

## Shortcut/App integration example

On iPhone, a Shortcut or app can:

1. collect domains, cookies, or app metadata from its own permitted context
2. `POST` the observations to `/api/privacy/reports`
3. inspect the returned `blockedRecommendations`
4. send selected blocks to `/api/privacy/devices/:deviceId/block`
5. fetch `/api/privacy/devices/:deviceId/block` and enforce that blocklist locally
6. send connection attempts to `/api/privacy/connections`, then wait for allow/deny review results

## Connection review model

- New connections are recorded with transport, target, service, app, and requested data types.
- The backend only stores metadata needed for review; it does not attempt arbitrary harvesting from remote devices.
- Unknown connections return `promptRequired: true` so a client can ask you to allow or deny.
- Manual decisions can be remembered and reused for later matching connections.

## OpenAPI-style contract

A machine-readable contract is available at `/home/runner/work/stargazers-log/stargazers-log/openapi.json`.

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

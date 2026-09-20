# stargazers-log

Minimal Node backend for an iPhone control agent.

## What it does

This service accepts safe, allow-listed action requests for a registered iPhone device, queues them for pickup by an iPhone client, and records execution results.

Supported actions:
- `open_app`
- `open_url`
- `send_text`
- `run_shortcut`

## API flow

1. Register a device with `POST /api/devices/register`
2. Submit a prompt or explicit actions to `POST /api/agent/commands`
3. Let the iPhone client poll `GET /api/devices/:deviceId/commands/next`
4. Send execution results to `POST /api/devices/:deviceId/commands/:commandId/result`
5. Read status from `GET /api/agent/commands/:commandId`

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

## Test

```bash
npm test
```

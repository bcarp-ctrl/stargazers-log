const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');

async function startServer() {
  const app = createApp({ apiToken: 'test-token' });
  const server = app.createServer();

  await new Promise((resolve) => server.listen(0, resolve));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const headers = {
    'x-agent-token': 'test-token',
    'content-type': 'application/json',
  };

  return {
    server,
    baseUrl,
    headers,
    async close() {
      await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}

test('health endpoint reports supported actions', async () => {
  const app = createApp({ apiToken: 'test-token' });
  const server = app.createServer();
  await new Promise((resolve) => server.listen(0, resolve));

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/health`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.supportedActions, ['open_app', 'open_url', 'send_text', 'run_shortcut']);

  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

test('registers a device and dispatches prompt-derived commands', async () => {
  const ctx = await startServer();

  const registerResponse = await fetch(`${ctx.baseUrl}/api/devices/register`, {
    method: 'POST',
    headers: ctx.headers,
    body: JSON.stringify({ deviceId: 'iphone-1', name: 'Primary iPhone' }),
  });
  assert.equal(registerResponse.status, 201);

  const commandResponse = await fetch(`${ctx.baseUrl}/api/agent/commands`, {
    method: 'POST',
    headers: ctx.headers,
    body: JSON.stringify({ deviceId: 'iphone-1', prompt: 'open safari' }),
  });
  const commandBody = await commandResponse.json();

  assert.equal(commandResponse.status, 201);
  assert.equal(commandBody.queued, 1);
  assert.equal(commandBody.commands[0].type, 'open_app');
  assert.equal(commandBody.commands[0].params.appName, 'safari');

  const nextResponse = await fetch(`${ctx.baseUrl}/api/devices/iphone-1/commands/next`, {
    headers: { 'x-agent-token': 'test-token' },
  });
  const nextBody = await nextResponse.json();

  assert.equal(nextResponse.status, 200);
  assert.equal(nextBody.command.status, 'dispatched');

  const resultResponse = await fetch(`${ctx.baseUrl}/api/devices/iphone-1/commands/${nextBody.command.id}/result`, {
    method: 'POST',
    headers: ctx.headers,
    body: JSON.stringify({ status: 'completed', result: 'Safari opened.' }),
  });
  const resultBody = await resultResponse.json();

  assert.equal(resultResponse.status, 200);
  assert.equal(resultBody.status, 'completed');

  const statusResponse = await fetch(`${ctx.baseUrl}/api/agent/commands/${nextBody.command.id}`, {
    headers: { 'x-agent-token': 'test-token' },
  });
  const statusBody = await statusResponse.json();

  assert.equal(statusResponse.status, 200);
  assert.equal(statusBody.result, 'Safari opened.');

  await ctx.close();
});

test('rejects unsupported actions', async () => {
  const ctx = await startServer();

  await fetch(`${ctx.baseUrl}/api/devices/register`, {
    method: 'POST',
    headers: ctx.headers,
    body: JSON.stringify({ deviceId: 'iphone-2' }),
  });

  const response = await fetch(`${ctx.baseUrl}/api/agent/commands`, {
    method: 'POST',
    headers: ctx.headers,
    body: JSON.stringify({
      deviceId: 'iphone-2',
      actions: [{ type: 'delete_everything', params: {} }],
    }),
  });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /Unsupported action type/);

  await ctx.close();
});

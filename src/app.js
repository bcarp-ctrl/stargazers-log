const http = require('node:http');
const { normalizeActions, SUPPORTED_ACTIONS } = require('./actions');

function createApp({ apiToken = process.env.AGENT_API_TOKEN } = {}) {
  const devices = new Map();
  const results = new Map();

  function getDevice(deviceId) {
    return devices.get(deviceId);
  }

  function ensureAuthorized(req) {
    if (!apiToken) {
      return true;
    }

    const tokenHeader = req.headers['x-agent-token'] || '';
    return tokenHeader === apiToken;
  }

  function json(res, statusCode, payload) {
    res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(payload));
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024 * 1024) {
          reject(new Error('Request body is too large.'));
          req.destroy();
        }
      });
      req.on('end', () => {
        if (!body) {
          resolve({});
          return;
        }

        try {
          resolve(JSON.parse(body));
        } catch {
          reject(new Error('Request body must be valid JSON.'));
        }
      });
      req.on('error', reject);
    });
  }

  async function handler(req, res) {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');

      if (url.pathname === '/health' && req.method === 'GET') {
        json(res, 200, { status: 'ok', supportedActions: Object.keys(SUPPORTED_ACTIONS) });
        return;
      }

      if (!ensureAuthorized(req)) {
        json(res, 401, { error: 'Unauthorized' });
        return;
      }

      if (url.pathname === '/api/devices/register' && req.method === 'POST') {
        const body = await readJson(req);
        const deviceId = String(body.deviceId || '').trim();
        const name = String(body.name || '').trim();

        if (!deviceId) {
          json(res, 400, { error: 'deviceId is required.' });
          return;
        }

        const device = devices.get(deviceId) || { queue: [] };
        device.id = deviceId;
        device.name = name || device.name || deviceId;
        device.updatedAt = new Date().toISOString();
        devices.set(deviceId, device);
        json(res, 201, { deviceId: device.id, name: device.name, updatedAt: device.updatedAt });
        return;
      }

      if (url.pathname === '/api/agent/commands' && req.method === 'POST') {
        const body = await readJson(req);
        const deviceId = String(body.deviceId || '').trim();

        if (!deviceId) {
          json(res, 400, { error: 'deviceId is required.' });
          return;
        }

        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const commands = normalizeActions({ prompt: body.prompt, actions: body.actions });
        device.queue.push(...commands);
        device.updatedAt = new Date().toISOString();

        json(res, 201, {
          deviceId,
          queued: commands.length,
          commands,
        });
        return;
      }

      const nextMatch = url.pathname.match(/^\/api\/devices\/([^/]+)\/commands\/next$/);
      if (nextMatch && req.method === 'GET') {
        const deviceId = decodeURIComponent(nextMatch[1]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const command = device.queue.find((item) => item.status === 'queued');
        if (!command) {
          json(res, 200, { command: null });
          return;
        }

        command.status = 'dispatched';
        command.dispatchedAt = new Date().toISOString();
        json(res, 200, { command });
        return;
      }

      const resultMatch = url.pathname.match(/^\/api\/devices\/([^/]+)\/commands\/([^/]+)\/result$/);
      if (resultMatch && req.method === 'POST') {
        const deviceId = decodeURIComponent(resultMatch[1]);
        const commandId = decodeURIComponent(resultMatch[2]);
        const device = getDevice(deviceId);

        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const command = device.queue.find((item) => item.id === commandId);
        if (!command) {
          json(res, 404, { error: 'Command not found.' });
          return;
        }

        const body = await readJson(req);
        const status = String(body.status || '').trim();
        if (!['completed', 'failed'].includes(status)) {
          json(res, 400, { error: 'status must be completed or failed.' });
          return;
        }

        command.status = status;
        command.result = typeof body.result === 'string' ? body.result : '';
        command.completedAt = new Date().toISOString();
        results.set(command.id, {
          deviceId,
          commandId: command.id,
          status: command.status,
          result: command.result,
          completedAt: command.completedAt,
        });

        json(res, 200, results.get(command.id));
        return;
      }

      const statusMatch = url.pathname.match(/^\/api\/agent\/commands\/([^/]+)$/);
      if (statusMatch && req.method === 'GET') {
        const commandId = decodeURIComponent(statusMatch[1]);
        const result = results.get(commandId);
        if (!result) {
          json(res, 404, { error: 'Command result not found.' });
          return;
        }

        json(res, 200, result);
        return;
      }

      json(res, 404, { error: 'Not found' });
    } catch (error) {
      json(res, 400, { error: error.message });
    }
  }

  return {
    handler,
    createServer() {
      return http.createServer(handler);
    },
  };
}

module.exports = {
  createApp,
};

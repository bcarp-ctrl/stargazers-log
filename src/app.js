const crypto = require('node:crypto');
const http = require('node:http');
const { normalizeActions, SUPPORTED_ACTIONS } = require('./actions');
const { analyzePrivacyReport, ensureDevicePrivacyState, mergeBlockedItems } = require('./privacy');

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
        json(res, 200, {
          status: 'ok',
          supportedActions: Object.keys(SUPPORTED_ACTIONS),
          privacyFeatures: ['tracker-detection', 'origin-tracing', 'block-recommendations'],
        });
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
        ensureDevicePrivacyState(device);
        devices.set(deviceId, device);
        json(res, 201, { deviceId: device.id, name: device.name, updatedAt: device.updatedAt });
        return;
      }

      if (url.pathname === '/api/privacy/reports' && req.method === 'POST') {
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

        const privacyState = ensureDevicePrivacyState(device);
        const analysis = analyzePrivacyReport({ observations: body.observations });
        const report = {
          id: crypto.randomUUID(),
          createdAt: new Date().toISOString(),
          summary: analysis.summary,
          observations: analysis.observations,
          findings: analysis.findings,
        };

        privacyState.reports.push(report);
        privacyState.findings.push(...analysis.findings);
        if (body.autoBlock) {
          privacyState.blocked = mergeBlockedItems(
            privacyState.blocked,
            analysis.blockedRecommendations.map((item) => ({
              ...item,
              createdAt: new Date().toISOString(),
            })),
          );
        }

        json(res, 201, {
          deviceId,
          reportId: report.id,
          summary: analysis.summary,
          findings: analysis.findings,
          blockedRecommendations: analysis.blockedRecommendations,
          blocked: privacyState.blocked,
        });
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

      const privacyStatusMatch = url.pathname.match(/^\/api\/privacy\/devices\/([^/]+)\/status$/);
      if (privacyStatusMatch && req.method === 'GET') {
        const deviceId = decodeURIComponent(privacyStatusMatch[1]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const privacyState = ensureDevicePrivacyState(device);
        json(res, 200, {
          deviceId,
          reports: privacyState.reports,
          findings: privacyState.findings,
          blocked: privacyState.blocked,
        });
        return;
      }

      const privacyBlockMatch = url.pathname.match(/^\/api\/privacy\/devices\/([^/]+)\/block$/);
      if (privacyBlockMatch && req.method === 'GET') {
        const deviceId = decodeURIComponent(privacyBlockMatch[1]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const privacyState = ensureDevicePrivacyState(device);
        json(res, 200, {
          deviceId,
          exportedAt: new Date().toISOString(),
          blockCount: privacyState.blocked.length,
          blocked: privacyState.blocked,
        });
        return;
      }

      if (privacyBlockMatch && req.method === 'POST') {
        const deviceId = decodeURIComponent(privacyBlockMatch[1]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const body = await readJson(req);
        if (!Array.isArray(body.items) || body.items.length === 0) {
          json(res, 400, { error: 'items must be a non-empty array.' });
          return;
        }

        const items = body.items.map((item) => {
          if (!item || typeof item !== 'object') {
            throw new Error('Each block item must be an object.');
          }

          const type = String(item.type || '').trim();
          const target = String(item.target || '').trim().toLowerCase();
          if (!['domain', 'app'].includes(type) || !target) {
            throw new Error('Block items require a type of domain or app and a target.');
          }

          return {
            type,
            target,
            reason: String(item.reason || '').trim(),
            createdAt: new Date().toISOString(),
          };
        });

        const privacyState = ensureDevicePrivacyState(device);
        privacyState.blocked = mergeBlockedItems(privacyState.blocked, items);
        json(res, 200, { deviceId, blocked: privacyState.blocked });
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

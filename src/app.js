const crypto = require('node:crypto');
const http = require('node:http');
const { normalizeActions, SUPPORTED_ACTIONS } = require('./actions');
const {
  analyzeConnectionEvent,
  analyzePrivacyReport,
  analyzeSniffReport,
  ensureDevicePrivacyState,
  mergeBlockedItems,
  normalizeConnectionEvent,
} = require('./privacy');
const { renderDashboardHtml } = require('./ui');

function createApp({ apiToken = process.env.AGENT_API_TOKEN } = {}) {
  const MAX_DEVICES = 200;
  const MAX_COMMANDS_PER_DEVICE = 500;
  const MAX_REPORTS_PER_DEVICE = 200;
  const MAX_SNIFF_REPORTS_PER_DEVICE = 200;
  const MAX_CONNECTIONS_PER_DEVICE = 500;
  const MAX_REVIEW_QUEUE_PER_DEVICE = 200;
  const MAX_SAVED_CONNECTIONS_PER_DEVICE = 500;
  const MAX_FINDINGS_PER_DEVICE = 5000;
  const MAX_BLOCKED_ITEMS_PER_DEVICE = 1000;
  const devices = new Map();
  const results = new Map();

  function createBadRequestError(message) {
    const error = new Error(message);
    error.statusCode = 400;
    return error;
  }

  function trimArray(items, maxItems) {
    if (items.length > maxItems) {
      items.splice(0, items.length - maxItems);
    }
  }

  function trimDeviceState(device) {
    const privacyState = ensureDevicePrivacyState(device);
    trimArray(device.queue, MAX_COMMANDS_PER_DEVICE);
    trimArray(privacyState.reports, MAX_REPORTS_PER_DEVICE);
    trimArray(privacyState.sniffReports, MAX_SNIFF_REPORTS_PER_DEVICE);
    trimArray(privacyState.connections, MAX_CONNECTIONS_PER_DEVICE);
    trimArray(privacyState.reviewQueue, MAX_REVIEW_QUEUE_PER_DEVICE);
    trimArray(privacyState.savedConnections, MAX_SAVED_CONNECTIONS_PER_DEVICE);
    trimArray(privacyState.findings, MAX_FINDINGS_PER_DEVICE);
    trimArray(privacyState.blocked, MAX_BLOCKED_ITEMS_PER_DEVICE);

    const activeCommandIds = new Set(device.queue.map((command) => command.id));
    for (const [commandId, result] of results.entries()) {
      if (result.deviceId === device.id && !activeCommandIds.has(commandId)) {
        results.delete(commandId);
      }
    }
  }

  function trimGlobalState() {
    while (devices.size > MAX_DEVICES) {
      const firstKey = devices.keys().next().value;
      const evictedDevice = devices.get(firstKey);
      devices.delete(firstKey);

      if (evictedDevice) {
        for (const command of evictedDevice.queue || []) {
          results.delete(command.id);
        }
      }
    }
  }

  function parseStrictBoolean(value, fieldName) {
    if (value === undefined) {
      return false;
    }

    if (typeof value !== 'boolean') {
      throw createBadRequestError(`${fieldName} must be a boolean.`);
    }

    return value;
  }

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
          reject(createBadRequestError('Request body is too large.'));
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
          reject(createBadRequestError('Request body must be valid JSON.'));
        }
      });
      req.on('error', reject);
    });
  }

  async function handler(req, res) {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');

      if (url.pathname === '/' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(renderDashboardHtml());
        return;
      }

      if (url.pathname === '/health' && req.method === 'GET') {
        json(res, 200, {
          status: 'ok',
          supportedActions: Object.keys(SUPPORTED_ACTIONS),
          privacyFeatures: ['tracker-detection', 'origin-tracing', 'block-recommendations', 'packet-sniffing', 'connection-review', 'ui'],
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
        trimDeviceState(device);
        trimGlobalState();
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
        const autoBlock = parseStrictBoolean(body.autoBlock, 'autoBlock');
        let analysis;
        try {
          analysis = analyzePrivacyReport({ observations: body.observations });
        } catch (error) {
          throw createBadRequestError(error.message);
        }
        const report = {
          id: crypto.randomUUID(),
          createdAt: new Date().toISOString(),
          summary: analysis.summary,
          observations: analysis.observations,
          findings: analysis.findings,
        };

        privacyState.reports.push(report);
        privacyState.findings.push(...analysis.findings);
        if (autoBlock) {
          privacyState.blocked = mergeBlockedItems(
            privacyState.blocked,
            analysis.blockedRecommendations.map((item) => ({
              ...item,
              createdAt: new Date().toISOString(),
            })),
          );
        }
        trimDeviceState(device);

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

      if (url.pathname === '/api/privacy/sniff' && req.method === 'POST') {
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
        const autoBlock = parseStrictBoolean(body.autoBlock, 'autoBlock');
        let analysis;
        try {
          analysis = analyzeSniffReport({ captures: body.captures });
        } catch (error) {
          throw createBadRequestError(error.message);
        }
        const report = {
          id: crypto.randomUUID(),
          createdAt: new Date().toISOString(),
          summary: analysis.summary,
          captures: analysis.captures,
          findings: analysis.findings,
        };

        privacyState.sniffReports.push(report);
        privacyState.findings.push(...analysis.findings);
        if (autoBlock) {
          privacyState.blocked = mergeBlockedItems(
            privacyState.blocked,
            analysis.blockedRecommendations.map((item) => ({
              ...item,
              createdAt: new Date().toISOString(),
            })),
          );
        }
        trimDeviceState(device);

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

      if (url.pathname === '/api/privacy/connections' && req.method === 'POST') {
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
        let connection;
        try {
          connection = normalizeConnectionEvent(body.connection);
        } catch (error) {
          throw createBadRequestError(error.message);
        }
        const analysis = analyzeConnectionEvent(connection);
        const blockedMatch = privacyState.blocked.find((item) =>
          (item.type === 'domain' && item.target === connection.remoteHost)
          || (item.type === 'app' && item.target === connection.appBundleId),
        );
        const savedMatch = analysis.policyKey
          ? privacyState.savedConnections.find((item) => item.policyKey === analysis.policyKey)
          : null;

        let decision = 'prompt';
        let decisionSource = 'review';
        if (blockedMatch) {
          decision = 'deny';
          decisionSource = 'blocklist';
        } else if (savedMatch) {
          decision = savedMatch.decision;
          decisionSource = 'saved';
        }

        const event = {
          id: connection.id,
          createdAt: new Date().toISOString(),
          connection,
          findings: analysis.findings,
          policyKey: analysis.policyKey,
          decision,
          decisionSource,
        };

        privacyState.connections.push(event);
        privacyState.findings.push(...analysis.findings);
        if (decision === 'prompt') {
          privacyState.reviewQueue.push(event);
        }
        trimDeviceState(device);

        json(res, 201, {
          deviceId,
          eventId: event.id,
          decision,
          decisionSource,
          promptRequired: decision === 'prompt',
          findings: analysis.findings,
          blockedRecommendations: analysis.blockedRecommendations,
          connection: event.connection,
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

        let commands;
        try {
          commands = normalizeActions({ prompt: body.prompt, actions: body.actions });
        } catch (error) {
          throw createBadRequestError(error.message);
        }
        device.queue.push(...commands);
        device.updatedAt = new Date().toISOString();
        trimDeviceState(device);

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

        if (command.status !== 'dispatched') {
          json(res, 409, { error: 'Command must be dispatched before submitting a result.' });
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
        trimDeviceState(device);
        trimGlobalState();

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
          sniffReports: privacyState.sniffReports,
          connections: privacyState.connections,
          reviewQueue: privacyState.reviewQueue,
          savedConnections: privacyState.savedConnections,
          findings: privacyState.findings,
          blocked: privacyState.blocked,
        });
        return;
      }

      const privacyReviewMatch = url.pathname.match(/^\/api\/privacy\/devices\/([^/]+)\/review$/);
      if (privacyReviewMatch && req.method === 'GET') {
        const deviceId = decodeURIComponent(privacyReviewMatch[1]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const privacyState = ensureDevicePrivacyState(device);
        json(res, 200, {
          deviceId,
          pending: privacyState.reviewQueue,
        });
        return;
      }

      const privacyReviewDecisionMatch = url.pathname.match(/^\/api\/privacy\/devices\/([^/]+)\/review\/([^/]+)$/);
      if (privacyReviewDecisionMatch && req.method === 'POST') {
        const deviceId = decodeURIComponent(privacyReviewDecisionMatch[1]);
        const eventId = decodeURIComponent(privacyReviewDecisionMatch[2]);
        const device = getDevice(deviceId);
        if (!device) {
          json(res, 404, { error: 'Device not registered.' });
          return;
        }

        const privacyState = ensureDevicePrivacyState(device);
        const event = privacyState.reviewQueue.find((item) => item.id === eventId);
        if (!event) {
          json(res, 404, { error: 'Connection event not found.' });
          return;
        }

        const body = await readJson(req);
        const decision = String(body.decision || '').trim().toLowerCase();
        if (!['allow', 'deny'].includes(decision)) {
          json(res, 400, { error: 'decision must be allow or deny.' });
          return;
        }

        event.decision = decision;
        event.decisionSource = 'manual';
        privacyState.reviewQueue = privacyState.reviewQueue.filter((item) => item.id !== event.id);

        if (body.remember !== undefined && typeof body.remember !== 'boolean') {
          json(res, 400, { error: 'remember must be a boolean.' });
          return;
        }

        if (body.remember) {
          if (!event.policyKey) {
            json(res, 400, { error: 'Cannot remember a decision without an identifying target.' });
            return;
          }

          privacyState.savedConnections = [
            ...privacyState.savedConnections.filter((item) => item.policyKey !== event.policyKey),
            {
              policyKey: event.policyKey,
              decision,
              label: event.connection.remoteHost || event.connection.remoteDeviceName || event.connection.appName || event.connection.service || event.connection.transport,
              createdAt: new Date().toISOString(),
            },
          ];
        }

        if (decision === 'deny') {
          const denyBlocks = event.findings
            .filter((finding) => finding.block)
            .map((finding) => ({
              ...finding.block,
              reason: finding.reason,
              createdAt: new Date().toISOString(),
            }));
          privacyState.blocked = mergeBlockedItems(privacyState.blocked, denyBlocks);
        }
        trimDeviceState(device);

        json(res, 200, {
          deviceId,
          eventId: event.id,
          decision: event.decision,
          savedConnections: privacyState.savedConnections,
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
            throw createBadRequestError('Each block item must be an object.');
          }

          const type = String(item.type || '').trim();
          const target = String(item.target || '').trim().toLowerCase();
          if (!['domain', 'app'].includes(type) || !target) {
            throw createBadRequestError('Block items require a type of domain or app and a target.');
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
        trimDeviceState(device);
        json(res, 200, { deviceId, blocked: privacyState.blocked });
        return;
      }

      json(res, 404, { error: 'Not found' });
    } catch (error) {
      if (error && error.statusCode === 400) {
        json(res, 400, { error: error.message });
        return;
      }

      json(res, 500, { error: 'Internal server error.' });
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

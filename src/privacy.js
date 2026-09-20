const crypto = require('node:crypto');

function ensureDevicePrivacyState(device) {
  if (!device.privacy) {
    device.privacy = {
      reports: [],
      sniffReports: [],
      connections: [],
      reviewQueue: [],
      savedConnections: [],
      findings: [],
      blocked: [],
    };
  }

  return device.privacy;
}

function normalizeObservation(observation) {
  if (!observation || typeof observation !== 'object') {
    throw new Error('Each privacy observation must be an object.');
  }

  const kind = String(observation.kind || '').trim();
  if (!['cookie', 'app'].includes(kind)) {
    throw new Error('Observation kind must be cookie or app.');
  }

  if (kind === 'cookie') {
    const name = String(observation.name || '').trim();
    const domain = String(observation.domain || '').trim().toLowerCase();
    if (!name || !domain) {
      throw new Error('Cookie observations require name and domain.');
    }

    const maxAgeDays = Number.isFinite(observation.maxAgeDays) ? observation.maxAgeDays : null;
    return {
      id: crypto.randomUUID(),
      kind,
      name,
      domain,
      sourceApp: String(observation.sourceApp || '').trim(),
      expiresAt: String(observation.expiresAt || '').trim(),
      maxAgeDays,
      sameSite: String(observation.sameSite || '').trim().toLowerCase(),
      partitioned: Boolean(observation.partitioned),
      httpOnly: Boolean(observation.httpOnly),
      secure: Boolean(observation.secure),
    };
  }

  const name = String(observation.name || '').trim();
  const bundleId = String(observation.bundleId || '').trim();
  if (!name || !bundleId) {
    throw new Error('App observations require name and bundleId.');
  }

  const domains = Array.isArray(observation.domains)
    ? observation.domains
      .map((domain) => String(domain || '').trim().toLowerCase())
      .filter(Boolean)
    : [];

  const permissions = Array.isArray(observation.permissions)
    ? observation.permissions
      .map((permission) => String(permission || '').trim().toLowerCase())
      .filter(Boolean)
    : [];

  return {
    id: crypto.randomUUID(),
    kind,
    name,
    bundleId,
    vendor: String(observation.vendor || '').trim(),
    sourceApp: String(observation.sourceApp || '').trim(),
    domains,
    permissions,
  };
}

function findCookieIssues(observation) {
  const issues = [];

  if (observation.maxAgeDays !== null && observation.maxAgeDays >= 365) {
    issues.push({
      category: 'supercookie',
      severity: 'high',
      reason: 'Cookie remains valid for a year or longer.',
      origin: {
        type: 'domain',
        value: observation.domain,
        sourceApp: observation.sourceApp || null,
      },
      block: {
        type: 'domain',
        target: observation.domain,
      },
    });
  }

  if (observation.domain.startsWith('.') && !observation.partitioned) {
    issues.push({
      category: 'cross-site-cookie',
      severity: 'medium',
      reason: 'Cookie is scoped broadly and is not partitioned.',
      origin: {
        type: 'domain',
        value: observation.domain,
        sourceApp: observation.sourceApp || null,
      },
      block: {
        type: 'domain',
        target: observation.domain,
      },
    });
  }

  if (!observation.sameSite || observation.sameSite === 'none') {
    issues.push({
      category: 'tracking-cookie',
      severity: 'medium',
      reason: 'Cookie can participate in cross-site tracking.',
      origin: {
        type: 'domain',
        value: observation.domain,
        sourceApp: observation.sourceApp || null,
      },
      block: {
        type: 'domain',
        target: observation.domain,
      },
    });
  }

  return issues;
}

function findAppIssues(observation) {
  const issues = [];
  const trackingPermissions = ['tracking', 'apptrackingtransparency', 'contacts', 'photos'];

  if (observation.domains.length >= 3) {
    issues.push({
      category: 'multi-origin-tracker',
      severity: 'medium',
      reason: 'App communicates with several origins that may correlate user activity.',
      origin: {
        type: 'app',
        value: observation.bundleId,
        sourceApp: observation.name,
      },
      block: {
        type: 'app',
        target: observation.bundleId,
      },
    });
  }

  if (observation.permissions.some((permission) => trackingPermissions.includes(permission))) {
    issues.push({
      category: 'sensitive-permissions',
      severity: 'medium',
      reason: 'App requests permissions commonly used for tracking or profiling.',
      origin: {
        type: 'app',
        value: observation.bundleId,
        sourceApp: observation.name,
      },
      block: {
        type: 'app',
        target: observation.bundleId,
      },
    });
  }

  return issues;
}

function dedupeBlockedItems(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.type}:${item.target}`;
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

function analyzePrivacyReport(report) {
  if (!report || typeof report !== 'object') {
    throw new Error('Privacy report must be an object.');
  }

  if (!Array.isArray(report.observations) || report.observations.length === 0) {
    throw new Error('Privacy report requires a non-empty observations array.');
  }

  const observations = report.observations.map(normalizeObservation);
  const findings = observations.flatMap((observation) => {
    const issues = observation.kind === 'cookie'
      ? findCookieIssues(observation)
      : findAppIssues(observation);

    return issues.map((issue) => ({
      id: crypto.randomUUID(),
      observationId: observation.id,
      kind: observation.kind,
      name: observation.kind === 'cookie' ? observation.name : observation.name,
      ...issue,
    }));
  });

  const blockedRecommendations = dedupeBlockedItems(findings.map((finding) => ({
    ...finding.block,
    reason: finding.reason,
    findingId: finding.id,
  })));

  return {
    summary: {
      observations: observations.length,
      findings: findings.length,
      blockedRecommendations: blockedRecommendations.length,
    },
    observations,
    findings,
    blockedRecommendations,
  };
}

function mergeBlockedItems(existingItems, nextItems) {
  return dedupeBlockedItems([...(existingItems || []), ...(nextItems || [])]);
}

function normalizeCapture(capture) {
  if (!capture || typeof capture !== 'object') {
    throw new Error('Each capture must be an object.');
  }

  const channel = String(capture.channel || '').trim().toLowerCase();
  if (!['wifi', 'cellular', 'bluetooth', 'airdrop'].includes(channel)) {
    throw new Error('Capture channel must be wifi, cellular, bluetooth, or airdrop.');
  }

  const packetCount = Number.isFinite(capture.packetCount) ? capture.packetCount : 1;
  const bytes = Number.isFinite(capture.bytes) ? capture.bytes : 0;

  return {
    id: crypto.randomUUID(),
    channel,
    remoteHost: String(capture.remoteHost || '').trim().toLowerCase(),
    protocol: String(capture.protocol || '').trim().toLowerCase(),
    purpose: String(capture.purpose || '').trim().toLowerCase(),
    appName: String(capture.appName || '').trim(),
    appBundleId: String(capture.appBundleId || '').trim(),
    advertiserId: String(capture.advertiserId || '').trim().toLowerCase(),
    serviceUuid: String(capture.serviceUuid || '').trim().toLowerCase(),
    packetCount,
    bytes,
  };
}

function keywordTrackerMatch(value) {
  return /(track|ads|analytics|beacon|metric|fingerprint)/i.test(value);
}

function findCaptureIssues(capture) {
  const issues = [];

  if (['wifi', 'cellular'].includes(capture.channel) && capture.remoteHost && keywordTrackerMatch(capture.remoteHost)) {
    issues.push({
      category: 'network-tracker',
      severity: 'medium',
      reason: `Potential tracking host seen on ${capture.channel}.`,
      origin: {
        type: 'domain',
        value: capture.remoteHost,
        sourceApp: capture.appName || capture.appBundleId || null,
        channel: capture.channel,
      },
      block: {
        type: 'domain',
        target: capture.remoteHost,
      },
    });
  }

  if (['bluetooth', 'airdrop'].includes(capture.channel) && (capture.advertiserId || capture.serviceUuid)) {
    issues.push({
      category: 'proximity-tracker',
      severity: 'medium',
      reason: `Persistent nearby identifier observed over ${capture.channel}.`,
      origin: {
        type: 'identifier',
        value: capture.advertiserId || capture.serviceUuid,
        sourceApp: capture.appName || capture.appBundleId || null,
        channel: capture.channel,
      },
      block: capture.appBundleId
        ? {
          type: 'app',
          target: capture.appBundleId,
        }
        : null,
    });
  }

  return issues;
}

function analyzeSniffReport(report) {
  if (!report || typeof report !== 'object') {
    throw new Error('Sniff report must be an object.');
  }

  if (!Array.isArray(report.captures) || report.captures.length === 0) {
    throw new Error('Sniff report requires a non-empty captures array.');
  }

  const captures = report.captures.map(normalizeCapture);
  const findings = captures.flatMap((capture) => findCaptureIssues(capture).map((issue) => ({
    id: crypto.randomUUID(),
    captureId: capture.id,
    kind: 'capture',
    name: capture.remoteHost || capture.appName || capture.appBundleId || capture.channel,
    ...issue,
  })));

  const hostChannels = new Map();
  for (const capture of captures) {
    if (!capture.remoteHost) {
      continue;
    }

    const channels = hostChannels.get(capture.remoteHost) || new Set();
    channels.add(capture.channel);
    hostChannels.set(capture.remoteHost, channels);
  }

  for (const [remoteHost, channels] of hostChannels.entries()) {
    if (channels.size >= 2) {
      findings.push({
        id: crypto.randomUUID(),
        kind: 'capture',
        name: remoteHost,
        category: 'cross-transport-tracker',
        severity: 'high',
        reason: `Origin observed across ${Array.from(channels).join(', ')} transports.`,
        origin: {
          type: 'domain',
          value: remoteHost,
          channels: Array.from(channels),
        },
        block: {
          type: 'domain',
          target: remoteHost,
        },
      });
    }
  }

  const blockedRecommendations = dedupeBlockedItems(
    findings
      .filter((finding) => finding.block)
      .map((finding) => ({
        ...finding.block,
        reason: finding.reason,
        findingId: finding.id,
      })),
  );

  return {
    summary: {
      captures: captures.length,
      findings: findings.length,
      blockedRecommendations: blockedRecommendations.length,
      channels: Array.from(new Set(captures.map((capture) => capture.channel))),
    },
    captures,
    findings,
    blockedRecommendations,
  };
}

function normalizeConnectionEvent(connection) {
  if (!connection || typeof connection !== 'object') {
    throw new Error('Connection event must be an object.');
  }

  const transport = String(connection.transport || '').trim().toLowerCase();
  if (!['wifi', 'cellular', 'bluetooth', 'airdrop'].includes(transport)) {
    throw new Error('Connection transport must be wifi, cellular, bluetooth, or airdrop.');
  }

  const dataTypes = Array.isArray(connection.dataTypes)
    ? connection.dataTypes.map((value) => String(value || '').trim().toLowerCase()).filter(Boolean)
    : [];

  return {
    id: crypto.randomUUID(),
    transport,
    remoteDeviceName: String(connection.remoteDeviceName || '').trim(),
    remoteDeviceId: String(connection.remoteDeviceId || '').trim().toLowerCase(),
    remoteHost: String(connection.remoteHost || '').trim().toLowerCase(),
    appName: String(connection.appName || '').trim(),
    appBundleId: String(connection.appBundleId || '').trim(),
    service: String(connection.service || '').trim().toLowerCase(),
    direction: String(connection.direction || 'outbound').trim().toLowerCase(),
    dataTypes,
    notes: String(connection.notes || '').trim(),
  };
}

function policyKeyForConnection(connection) {
  return [
    connection.transport,
    connection.remoteHost || connection.remoteDeviceId || connection.appBundleId || connection.service || 'unknown',
  ].join(':');
}

function analyzeConnectionEvent(connection) {
  const findings = [];
  const sensitiveDataTypes = ['calendar', 'contacts', 'photos', 'location', 'messages'];

  if (connection.remoteHost && keywordTrackerMatch(connection.remoteHost)) {
    findings.push({
      id: crypto.randomUUID(),
      kind: 'connection',
      name: connection.remoteHost,
      category: 'tracker-connection',
      severity: 'medium',
      reason: `Connection target resembles a tracking endpoint over ${connection.transport}.`,
      origin: {
        type: 'domain',
        value: connection.remoteHost,
        sourceApp: connection.appName || connection.appBundleId || null,
        channel: connection.transport,
      },
      block: {
        type: 'domain',
        target: connection.remoteHost,
      },
    });
  }

  if (connection.dataTypes.some((dataType) => sensitiveDataTypes.includes(dataType))) {
    findings.push({
      id: crypto.randomUUID(),
      kind: 'connection',
      name: connection.remoteHost || connection.remoteDeviceName || connection.service || connection.transport,
      category: 'sensitive-data-egress',
      severity: 'high',
      reason: `Connection may expose sensitive data: ${connection.dataTypes.join(', ')}.`,
      origin: {
        type: connection.remoteHost ? 'domain' : 'device',
        value: connection.remoteHost || connection.remoteDeviceId || connection.remoteDeviceName || connection.service,
        sourceApp: connection.appName || connection.appBundleId || null,
        channel: connection.transport,
      },
      block: connection.appBundleId
        ? {
          type: 'app',
          target: connection.appBundleId,
        }
        : connection.remoteHost
          ? {
            type: 'domain',
            target: connection.remoteHost,
          }
          : null,
    });
  }

  if (['bluetooth', 'airdrop'].includes(connection.transport) && (connection.remoteDeviceId || connection.remoteDeviceName)) {
    findings.push({
      id: crypto.randomUUID(),
      kind: 'connection',
      name: connection.remoteDeviceName || connection.remoteDeviceId,
      category: 'nearby-device-connection',
      severity: 'medium',
      reason: `Nearby device connection observed over ${connection.transport}.`,
      origin: {
        type: 'device',
        value: connection.remoteDeviceId || connection.remoteDeviceName,
        sourceApp: connection.appName || connection.appBundleId || null,
        channel: connection.transport,
      },
      block: connection.appBundleId
        ? {
          type: 'app',
          target: connection.appBundleId,
        }
        : null,
    });
  }

  const blockedRecommendations = dedupeBlockedItems(
    findings
      .filter((finding) => finding.block)
      .map((finding) => ({
        ...finding.block,
        reason: finding.reason,
        findingId: finding.id,
      })),
  );

  return {
    connection,
    findings,
    blockedRecommendations,
    policyKey: policyKeyForConnection(connection),
  };
}

module.exports = {
  analyzePrivacyReport,
  analyzeConnectionEvent,
  analyzeSniffReport,
  ensureDevicePrivacyState,
  normalizeConnectionEvent,
  policyKeyForConnection,
  mergeBlockedItems,
};

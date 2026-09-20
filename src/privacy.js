const crypto = require('node:crypto');

function ensureDevicePrivacyState(device) {
  if (!device.privacy) {
    device.privacy = {
      reports: [],
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

module.exports = {
  analyzePrivacyReport,
  ensureDevicePrivacyState,
  mergeBlockedItems,
};

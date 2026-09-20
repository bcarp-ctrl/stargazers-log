const crypto = require('node:crypto');

const SUPPORTED_ACTIONS = {
  open_app: ['appName'],
  open_url: ['url'],
  send_text: ['recipient', 'message'],
  run_shortcut: ['shortcutName'],
};

function planPrompt(prompt) {
  const trimmed = String(prompt || '').trim();

  if (!trimmed) {
    throw new Error('Prompt is required when actions are not provided.');
  }

  const openUrl = trimmed.match(/(?:open|visit|go to)\s+(https?:\/\/\S+)/i);
  if (openUrl) {
    return [{ type: 'open_url', params: { url: openUrl[1] } }];
  }

  const openApp = trimmed.match(/open\s+([a-z0-9 ._-]+)$/i);
  if (openApp) {
    return [{ type: 'open_app', params: { appName: openApp[1].trim() } }];
  }

  const runShortcut = trimmed.match(/run\s+shortcut\s+(.+)$/i);
  if (runShortcut) {
    return [{ type: 'run_shortcut', params: { shortcutName: runShortcut[1].trim() } }];
  }

  const sendText = trimmed.match(/send\s+(?:a\s+)?text\s+to\s+(.+?)\s+saying\s+(.+)$/i);
  if (sendText) {
    return [{
      type: 'send_text',
      params: {
        recipient: sendText[1].trim(),
        message: sendText[2].trim(),
      },
    }];
  }

  throw new Error('Prompt could not be translated into a supported iPhone action.');
}

function validateAction(action) {
  if (!action || typeof action !== 'object') {
    throw new Error('Each action must be an object.');
  }

  const requiredFields = SUPPORTED_ACTIONS[action.type];
  if (!requiredFields) {
    throw new Error(`Unsupported action type: ${action.type}`);
  }

  if (!action.params || typeof action.params !== 'object') {
    throw new Error(`Action params are required for type: ${action.type}`);
  }

  for (const field of requiredFields) {
    const value = action.params[field];
    if (typeof value !== 'string' || !value.trim()) {
      throw new Error(`Action ${action.type} requires a non-empty string field: ${field}`);
    }
  }

  if (action.type === 'open_url') {
    let parsed;
    try {
      parsed = new URL(action.params.url);
    } catch {
      throw new Error('open_url requires a valid URL.');
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only http and https URLs are supported.');
    }
  }

  return {
    id: crypto.randomUUID(),
    type: action.type,
    params: Object.fromEntries(
      Object.entries(action.params).map(([key, value]) => [key, value.trim()]),
    ),
    status: 'queued',
    createdAt: new Date().toISOString(),
  };
}

function normalizeActions({ prompt, actions }) {
  const sourceActions = Array.isArray(actions) && actions.length > 0 ? actions : planPrompt(prompt);
  return sourceActions.map(validateAction);
}

module.exports = {
  SUPPORTED_ACTIONS,
  normalizeActions,
};

function renderDashboardHtml() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Privacy Tracker Dashboard</title>
    <style>
      :root { color-scheme: dark; }
      body { font-family: Arial, sans-serif; margin: 0; background: #111827; color: #f3f4f6; }
      main { max-width: 960px; margin: 0 auto; padding: 24px; }
      .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
      .card { background: #1f2937; border: 1px solid #374151; border-radius: 12px; padding: 16px; }
      input, textarea, button { width: 100%; box-sizing: border-box; margin-top: 8px; border-radius: 8px; border: 1px solid #4b5563; padding: 10px; background: #0f172a; color: #f3f4f6; }
      button { background: #2563eb; cursor: pointer; font-weight: 700; }
      pre { background: #0b1220; border-radius: 8px; padding: 12px; overflow: auto; white-space: pre-wrap; }
      label { display: block; margin-top: 12px; font-size: 14px; }
      h1, h2 { margin-top: 0; }
    </style>
  </head>
  <body>
    <main>
      <h1>Privacy Tracker Dashboard</h1>
      <p>Inspect device privacy findings, sync blocklists, and submit sniff captures across WiFi, cellular, Bluetooth, and AirDrop.</p>
      <div class="grid">
        <section class="card">
          <h2>Connection</h2>
          <label>Device ID<input id="deviceId" value="iphone-1" /></label>
          <button id="registerDevice">Register device</button>
          <label>API token<input id="token" placeholder="Optional x-agent-token" /></label>
          <button id="loadStatus">Load privacy status</button>
          <button id="loadBlocks">Load blocklist export</button>
          <button id="loadReview">Load review queue</button>
        </section>
        <section class="card">
          <h2>Submit sniff capture</h2>
          <label>Capture JSON</label>
          <textarea id="sniffPayload" rows="14">{
  "deviceId": "iphone-1",
  "autoBlock": true,
  "captures": [
    {
      "channel": "wifi",
      "remoteHost": "ads.example",
      "protocol": "https",
      "appName": "Safari",
      "packetCount": 12,
      "bytes": 4096
    },
    {
      "channel": "bluetooth",
      "advertiserId": "beacon-123",
      "appBundleId": "com.example.coupons",
      "appName": "Coupons+"
    }
  ]
}</textarea>
          <button id="submitSniff">Analyze sniff capture</button>
        </section>
        <section class="card">
          <h2>Submit connection event</h2>
          <textarea id="connectionPayload" rows="14">{
  "deviceId": "iphone-1",
  "connection": {
    "transport": "wifi",
    "remoteHost": "calendar-sync.example",
    "appName": "Calendar",
    "service": "caldav",
    "dataTypes": ["calendar"],
    "direction": "outbound"
  }
}</textarea>
          <button id="submitConnection">Review connection</button>
        </section>
      </div>
      <section class="card" style="margin-top:16px;">
        <h2>Output</h2>
        <pre id="output">Ready.</pre>
      </section>
    </main>
    <script>
      const output = document.getElementById('output');
      const deviceId = document.getElementById('deviceId');
      const token = document.getElementById('token');

      function headers(includeJson) {
        const result = {};
        if (token.value) result['x-agent-token'] = token.value;
        if (includeJson) result['Content-Type'] = 'application/json';
        return result;
      }

      async function callApi(path, options = {}) {
        const response = await fetch(path, options);
        const text = await response.text();
        try {
          return JSON.stringify(JSON.parse(text), null, 2);
        } catch {
          return text;
        }
      }

      async function registerDevice() {
        return callApi('/api/devices/register', {
          method: 'POST',
          headers: headers(true),
          body: JSON.stringify({ deviceId: deviceId.value }),
        });
      }

      document.getElementById('registerDevice').addEventListener('click', async () => {
        output.textContent = await registerDevice();
      });

      document.getElementById('loadStatus').addEventListener('click', async () => {
        output.textContent = await callApi('/api/privacy/devices/' + encodeURIComponent(deviceId.value) + '/status', {
          headers: headers(false),
        });
      });

      document.getElementById('loadBlocks').addEventListener('click', async () => {
        output.textContent = await callApi('/api/privacy/devices/' + encodeURIComponent(deviceId.value) + '/block', {
          headers: headers(false),
        });
      });

      document.getElementById('loadReview').addEventListener('click', async () => {
        output.textContent = await callApi('/api/privacy/devices/' + encodeURIComponent(deviceId.value) + '/review', {
          headers: headers(false),
        });
      });

      document.getElementById('submitSniff').addEventListener('click', async () => {
        await registerDevice();
        output.textContent = await callApi('/api/privacy/sniff', {
          method: 'POST',
          headers: headers(true),
          body: document.getElementById('sniffPayload').value,
        });
      });

      document.getElementById('submitConnection').addEventListener('click', async () => {
        await registerDevice();
        output.textContent = await callApi('/api/privacy/connections', {
          method: 'POST',
          headers: headers(true),
          body: document.getElementById('connectionPayload').value,
        });
      });
    </script>
  </body>
</html>`;
}

module.exports = {
  renderDashboardHtml,
};

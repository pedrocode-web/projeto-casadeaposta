const fetch = require('node-fetch');

async function verifyIdentity({ apiUrl, apiToken, cpf, firstName, lastName, dob }) {
  if (!apiUrl || !apiToken) return { ok: true, reason: 'Identity API not configured' };
  try {
    const res = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiToken}`,
      },
      body: JSON.stringify({ cpf, firstName, lastName, dob }),
    });
    if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
    const data = await res.json();
    return { ok: !!data?.match, reason: data?.reason || null };
  } catch (e) {
    return { ok: false, reason: 'request_failed' };
  }
}

module.exports = { verifyIdentity };


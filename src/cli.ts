// `mcp-proxy login | status | logout`: manages this node's own upstream login.
// Run inside the node's container:  docker compose exec proxy mcp-proxy login

import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { loadSettings } from './env';
import { UpstreamLogin } from './upstream-login';

const settings = loadSettings();
const login = new UpstreamLogin(join(settings.dataDir, 'upstream-login.json'), settings);
const command = process.argv[2] ?? 'status';

function printStatus(): void {
  const s = login.status();
  console.log(`upstream:  ${s.upstreamUrl}`);
  console.log(`signed in: ${s.connected ? 'yes' : 'no'}`);
  if (s.issuer) console.log(`auth server: ${s.issuer}${s.clientSource ? ` (client via ${s.clientSource})` : ''}`);
  if (s.scope) console.log(`scope:     ${s.scope}`);
  if (s.expiresAt) console.log(`token expires: ${new Date(s.expiresAt).toISOString()}${s.hasRefreshToken ? ', refreshes automatically' : ', no refresh token'}`);
  if (s.connectedAt) console.log(`signed in at: ${new Date(s.connectedAt).toISOString()}`);
  if (s.lastError) console.log(`last error: ${s.lastError}`);
}

/** Accepts the code from the landing page, the full redirected URL, or just its query string. */
function parsePasted(text: string): URLSearchParams {
  const trimmed = text.trim();
  const query = trimmed.includes('?') ? trimmed.slice(trimmed.indexOf('?') + 1) : trimmed;
  return new URLSearchParams(query.split('#')[0]);
}

switch (command) {
  case 'login': {
    const pending = await login.begin();
    console.log(`Signing this node in to ${settings.upstreamUrl}\n`);
    console.log('1. Open this link in a browser and sign in:\n');
    console.log(`   ${pending.url}\n`);
    console.log(`2. You'll land on ${settings.publicUrl}/upstream-callback. Copy the code shown there.\n`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const pasted = await rl.question('3. Paste it here: ');
    rl.close();
    await login.complete(pending, parsePasted(pasted));
    console.log('\nSigned in. This node joins the tunnel within a few seconds.\n');
    printStatus();
    break;
  }
  case 'logout':
    login.logout();
    console.log('Signed out. This node leaves the tunnel within a few seconds.');
    break;
  case 'status':
    printStatus();
    break;
  default:
    console.error('usage: mcp-proxy login | status | logout');
    process.exit(2);
}

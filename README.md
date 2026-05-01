# Keycloak Passkey Extension Integration (Quick Guide)

## Admin (Keycloak) quick summary

To enable this extension, Keycloak admins only need to install the provider and configure realm/client settings:

- Download the plugin JAR from the latest GitHub release, copy it to `keycloak/providers/`, then restart Keycloak.
- In the target realm, enable Passwordless WebAuthn and set the Passwordless RP ID to the host that will use passkeys.
- Ensure each app client that should use passkeys has correct `Web Origins` and `Redirect URIs` for your deployment.

## Dev quick summary

After admin setup is complete, app developers integrate the client flow:

- Serve a silent check-sso callback page (for example `/silent-check-sso.html`) and configure
  `silentCheckSsoRedirectUri`.
- Initialize Keycloak with `onLoad: 'check-sso'` (typically with `silentCheckSsoFallback: false`).
- Call `GET /realms/{realm}/passkey/{clientId}/challenge` before registration/authentication.
- Register passkeys via `POST /realms/{realm}/passkey/{clientId}/save` with `Authorization: Bearer <token>` and
  `credentials: 'include'`.
- Authenticate via `POST /realms/{realm}/passkey/{clientId}/authenticate` with `credentials: 'include'`, then run `check-sso` again
  to hydrate fresh tokens.

---

## How to use it?

This extension adds passkey APIs to Keycloak at:

`/realms/{realm}/passkey/*`

Endpoints (required client identification):

- `GET /{clientId}/challenge`
- `POST /{clientId}/save`
- `POST /{clientId}/authenticate`

## How the plugin works

The plugin is a Keycloak `RealmResourceProvider` mounted at `/realms/{realm}/passkey/*`.

1. `GET /{clientId}/challenge` creates a short-lived, single-use challenge in Keycloak server storage.
2. `POST /{clientId}/save` stores a verified passkey for the currently logged-in user (resolved from the bearer access token).
3. `POST /{clientId}/authenticate` verifies the WebAuthn assertion, completes the standard Keycloak browser login flow (including required actions), sets the Keycloak login cookie, and returns `204 No Content`.

How `check-sso` uses that session:

- The client calls `/authenticate` with `credentials: 'include'` so the Keycloak login cookie is written in the browser.
- After successful authentication, run `keycloak.init({ onLoad: 'check-sso' })` again to hydrate tokens from the new cookie-backed browser session (silent mode recommended).
- `check-sso` uses the existing Keycloak browser session (cookie) to silently authenticate and provide fresh tokens in `keycloak.token`/`keycloak.tokenParsed` for subsequent API calls.

## 1. Install from GitHub release

```bash
cp custom-endpoint-*.jar ../keycloak/providers/
```

1. Open [Releases](/releases/latest).
2. Download the `custom-endpoint-*.jar` asset.
3. Copy it to `keycloak/providers/` (example command above).
4. Restart Keycloak.

### 1.1 Build from source (optional)

```bash
mvn clean package
cp target/custom-endpoint-*.jar ../keycloak/providers/
```

## 2. Keycloak setup (no extension env vars)

No extension env var is required for client selection.

## 3. Configure realm/client

In your realm:

1. Enable Passwordless WebAuthn.
2. Set Passwordless RP ID to your app host (e.g. `localhost` in local dev).
3. Configure each app client that will use passkey login.
4. Add your client URL to `Web Origins`.
5. Add callback URLs to `Redirect URIs`.
6. Add your silent check-sso callback URL to `Redirect URIs` (for example `http://localhost:3000/silent-check-sso.html`, or covered by wildcard).

## 4. One client module (`keycloakClient.js`)

### 4.1 Add silent check-sso callback page

Create `public/silent-check-sso.html`:

```html
<!doctype html>
<html lang="en">
  <body>
    <script>parent.postMessage(location.href, location.origin);</script>
  </body>
</html>
```

### 4.2 Create one `keycloakClient.js`

```js
import Keycloak from 'keycloak-js';

const keycloakConfig = {
  url: 'http://localhost:8080',
  realm: 'demo',
  clientId: 'demo-app'
};

const checkSsoOptions = {
  onLoad: 'check-sso',
  pkceMethod: 'S256',
  silentCheckSsoRedirectUri: `${window.location.origin}/silent-check-sso.html`,
  silentCheckSsoFallback: false
};

let keycloak = new Keycloak(keycloakConfig);

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function passkeyUrl(path) {
  return `${keycloakConfig.url}/realms/${encodeURIComponent(keycloakConfig.realm)}/passkey/${encodeURIComponent(keycloakConfig.clientId)}/${path}`;
}

async function getChallenge() {
  const res = await fetch(passkeyUrl('challenge'), { credentials: 'include' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to get challenge');
  return body.challenge;
}

export async function initAuth() {
  keycloak = new Keycloak(keycloakConfig);
  return keycloak.init(checkSsoOptions);
}

export function loginWithPassword() {
  return keycloak.login({ redirectUri: window.location.href });
}

export async function registerPasskey() {
  if (!keycloak.authenticated || !keycloak.token) {
    throw new Error('User must be logged in first');
  }

  const challenge = await getChallenge();
  const userId = keycloak.tokenParsed?.sub;
  if (!userId) throw new Error('Access token subject is required');
  const username = keycloak.tokenParsed?.preferred_username || userId;
  const displayName = keycloak.tokenParsed?.name || username;
  const userIdBytes = new TextEncoder().encode(userId).slice(0, 64);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64Url(challenge),
      rp: { name: 'My App', id: window.location.hostname },
      user: { id: userIdBytes, name: username, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      attestation: 'none'
    }
  });

  const res = await fetch(passkeyUrl('save'), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${keycloak.token}`
    },
    body: JSON.stringify({
      credentialId: toBase64Url(credential.rawId),
      rawId: toBase64Url(credential.rawId),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      attestationObject: toBase64Url(credential.response.attestationObject),
      challenge
    })
  });

  if (!res.ok) throw new Error(await res.text());
}

export async function loginWithPasskey() {
  const challenge = await getChallenge();
  const assertion = await navigator.credentials.get({
    publicKey: { challenge: fromBase64Url(challenge), userVerification: 'preferred' }
  });

  const res = await fetch(passkeyUrl('authenticate'), {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      credentialId: toBase64Url(assertion.rawId),
      rawId: toBase64Url(assertion.rawId),
      userHandle: assertion.response.userHandle ? toBase64Url(assertion.response.userHandle) : null,
      clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
      authenticatorData: toBase64Url(assertion.response.authenticatorData),
      signature: toBase64Url(assertion.response.signature),
      challenge
    })
  });

  if (res.status !== 204) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Passkey auth failed: ${res.status}`);
  }

  const authenticated = await initAuth(); // silent check-sso refresh
  if (!authenticated) throw new Error('No session after passkey auth');
}

export function logout() {
  return keycloak.logout({ redirectUri: `${window.location.origin}/` });
}

export function getKeycloak() {
  return keycloak;
}
```

### 4.3 Use these functions from anywhere in your client

```js
import { initAuth, login, loginWithPasskey, registerPasskey, logout, getKeycloak } from './keycloakClient.js';

// call once on app startup
const authenticated = await initAuth();

// later, for example on button clicks
await loginWithPassword();

await loginWithPasskey();

await registerPasskey();

await logout();
```

## 5. Important notes

- Challenge TTL is `120s` and single-use.
- Client selection is done via path segment `/{clientId}/...`.
- `/challenge` and `/save` should be called with `credentials: 'include'` so auth cookies/sessions are preserved.
- `/save` requires `Authorization: Bearer <token>` and the issued registration `challenge`.
- `/authenticate` should be called with `credentials: 'include'`; on success it typically returns `204` after writing login cookies.
- Re-run `check-sso` after `/authenticate` to hydrate tokens into your SPA client (prefer `silentCheckSsoRedirectUri` + `silentCheckSsoFallback: false`).
- If you get CORS errors, fix the configured client `Web Origins`.

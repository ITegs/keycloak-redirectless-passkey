# Keycloak Passkey Extension Integration (Quick Guide)

This extension adds passkey APIs to Keycloak at:

`/realms/{realm}/passkey/*`

Endpoints:

- `GET /challenge`
- `POST /save`
- `POST /authenticate`

## How the plugin works

The plugin is a Keycloak `RealmResourceProvider` mounted at `/realms/{realm}/passkey/*`.

1. `GET /challenge` creates a short-lived, single-use challenge in Keycloak server storage.
2. `POST /save` stores a verified passkey for the currently logged-in user (resolved from the bearer access token).
3. `POST /authenticate` verifies the WebAuthn assertion and completes the standard Keycloak browser login flow (including required actions), setting the Keycloak login cookie.

How `check-sso` uses that session:

- The frontend calls `/authenticate` with `credentials: 'include'`, so the Keycloak session cookie is written in the browser.
- After a successful passkey login, the app redirects to `/` and runs `keycloak.init({ onLoad: 'check-sso' })`.
- `check-sso` uses the existing Keycloak browser session (cookie) to silently authenticate and provide fresh tokens in `keycloak.token`/`keycloak.tokenParsed` for subsequent API calls.

## 1. Build and deploy

```bash
cd keycloak-custom-passkey-login
mvn clean package
cp target/custom-endpoint-1.0-SNAPSHOT.jar ../keycloak/providers/
```

Restart Keycloak after copying the JAR.

## 2. Configure Keycloak env vars

- `KC_PASSKEY_CLIENT_ID`: OIDC client used by `/authenticate` to complete browser login flow.
- `KC_ALLOWED_BROWSER_ORIGIN`: CORS origin regex.

Example:

```env
KC_PASSKEY_CLIENT_ID=my-spa-client
KC_ALLOWED_BROWSER_ORIGIN=https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?
```

## 3. Configure realm/client

In your realm:

1. Enable Passwordless WebAuthn.
2. Set Passwordless RP ID to your app host (e.g. `localhost` in local dev).
3. Ensure client `clientId == KC_PASSKEY_CLIENT_ID`.
4. Add your frontend URL to `Web Origins`.
5. Add callback URLs to `Redirect URIs`.

## 4. Copy-paste frontend example

Create `passkeyClient.js` in your app:

```js
// passkeyClient.js
function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function passkeyBaseUrl({ keycloakUrl, realm }) {
  return `${keycloakUrl.replace(/\/$/, '')}/realms/${encodeURIComponent(realm)}/passkey`;
}

async function getJson(url, options = {}) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Request failed: ${res.status}`);
  return body;
}

export async function registerPasskey({
  keycloakUrl,
  realm,
  accessToken,
  username,
  displayName = username,
  rpName = 'My App'
}) {
  const baseUrl = passkeyBaseUrl({ keycloakUrl, realm });
  const { challenge } = await getJson(`${baseUrl}/challenge`, {
    credentials: 'include'
  });

  const userIdBytes = new TextEncoder().encode(username).slice(0, 64);
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64Url(challenge),
      rp: { name: rpName, id: window.location.hostname },
      user: { id: userIdBytes, name: username, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      attestation: 'none'
    }
  });

  if (!credential?.rawId || !credential?.response?.clientDataJSON || !credential?.response?.attestationObject) {
    throw new Error('Incomplete registration credential');
  }

  await fetch(`${baseUrl}/save`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      credentialId: toBase64Url(credential.rawId),
      rawId: toBase64Url(credential.rawId),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      attestationObject: toBase64Url(credential.response.attestationObject),
      challenge
    })
  }).then(async (res) => {
    if (!res.ok) throw new Error(await res.text());
  });
}

export async function authenticateWithPasskey({ keycloakUrl, realm }) {
  const baseUrl = passkeyBaseUrl({ keycloakUrl, realm });
  const { challenge } = await getJson(`${baseUrl}/challenge`, {
    credentials: 'include'
  });

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64Url(challenge),
      userVerification: 'preferred'
    }
  });

  if (!assertion?.rawId || !assertion?.response?.clientDataJSON || !assertion?.response?.authenticatorData || !assertion?.response?.signature) {
    throw new Error('Incomplete authentication assertion');
  }

  const res = await fetch(`${baseUrl}/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      credentialId: toBase64Url(assertion.rawId),
      rawId: toBase64Url(assertion.rawId),
      clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
      authenticatorData: toBase64Url(assertion.response.authenticatorData),
      signature: toBase64Url(assertion.response.signature),
      challenge
    })
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Passkey auth failed: ${res.status}`);
  }
}
```

### Usage example

```js
import { registerPasskey, authenticateWithPasskey } from './passkeyClient.js';

// after normal Keycloak login
await registerPasskey({
  keycloakUrl: 'http://localhost:8080',
  realm: 'demo',
  accessToken: keycloak.token,
  username: keycloak.tokenParsed.preferred_username,
  displayName: keycloak.tokenParsed.name
});

// login button: passkey-only auth
await authenticateWithPasskey({
  keycloakUrl: 'http://localhost:8080',
  realm: 'demo'
});
window.location.replace('/');
```

## 5. Important notes

- Challenge TTL is `120s` and single-use.
- `/challenge`, `/save`, and `/authenticate` should be called with `credentials: 'include'` so the auth-session cookie is preserved.
- `/save` requires `Authorization: Bearer <token>` and the issued registration `challenge`.
- `/authenticate` validates passkey + challenge and completes browser-flow login (it does not return tokens directly).
- If you get CORS errors, fix `KC_ALLOWED_BROWSER_ORIGIN` and client `Web Origins`.

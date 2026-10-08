# TylerOS Gateway

Cloudflare Worker authentication gateway for TylerOS.

## Trust boundary

The Worker is the authentication authority. The DMZ is a separate application/repository.

The DMZ never receives the Cloudflare signing private key.

### Worker secrets

Configure these as Cloudflare Worker secrets:

- `TURNSTILE_SECRET_KEY`
- `DMZ_SIGNING_PRIVATE_KEY_JWK` — P-256 private key used by the Worker to sign short-lived DMZ grants.
- `DMZ_SERVICE_PUBLIC_KEY_JWK` — P-256 public key belonging to the DMZ service.

### DMZ-held values

The separate DMZ application will hold:

- `CF_DMZ_SIGNING_PUBLIC_KEY_JWK` — public key corresponding to `DMZ_SIGNING_PRIVATE_KEY_JWK`.
- `DMZ_SERVICE_PRIVATE_KEY_JWK` — private key corresponding to `DMZ_SERVICE_PUBLIC_KEY_JWK`.

Never commit any private key to GitHub.

## DMZ protocol

1. WebAuthn authenticates the browser and creates a CF session.
2. The Worker creates a two-minute, single-use handoff.
3. `/transit` checks that the DMZ endpoint is reachable and obtains the handoff URL.
4. The DMZ application generates an ephemeral P-256 browser key.
5. The DMZ service authenticates its request to `/api/dmz/device/authorize` with its own private key.
6. The Worker verifies the handoff, CF session and DMZ service signature, then signs a grant containing the browser's public key.
7. The DMZ verifies the Cloudflare signature and challenges the browser.
8. The browser signs the challenge with its private key.
9. The DMZ service authenticates to `/api/dmz/grant/consume`.
10. The Worker atomically consumes the grant and promotes the CF session to the `dmz` stage.
11. The browser can access `tyleros.uk/*`.

The browser private key is generated and retained by the separate DMZ application. It is never sent to Cloudflare.

## Deploy

Install dependencies:

```bash
npm install
```

Apply the D1 migration:

```bash
npm run db:migrate:remote
```

Deploy:

```bash
npm run deploy
```

The existing WebAuthn/Turnstile secrets remain required.

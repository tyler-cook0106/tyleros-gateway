/// <reference types="@cloudflare/workers-types" />
import { Hono } from "hono";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";

type Bindings = {
  DB: D1Database;
  ASSETS: Fetcher;
  RP_NAME: string;
  RP_ID: string;
  ORIGIN: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  DMZ_ORIGIN: string;
  DMZ: Fetcher;
  DMZ_SIGNING_PRIVATE_KEY_JWK: string;
  DMZ_SERVICE_PUBLIC_KEY_JWK: string;
};

type SessionStage = "cf" | "dmz";

const app = new Hono<{ Bindings: Bindings }>();

const SESSION_COOKIE = "tyleros_session";
const HANDOFF_COOKIE = "tyleros_handoff";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_LEASE_MS = 15 * 1000;
const HEARTBEAT_MIN_INTERVAL_MS = 3 * 1000;
const HANDOFF_TTL_MS = 2 * 60 * 1000;
const DMZ_GRANT_TTL_MS = 2 * 60 * 1000;
const DMZ_REQUEST_SKEW_MS = 60 * 1000;

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomToken(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64url(value);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return base64url(new Uint8Array(digest));
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return new Uint8Array(digest);
}

async function importP256Key(jwkText: string, usages: KeyUsage[]): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkText) as JsonWebKey;
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    usages
  );
}

async function signP256(jwkText: string, value: string): Promise<string> {
  const key = await importP256Key(jwkText, ["sign"]);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(value)
  );
  return base64url(new Uint8Array(signature));
}

async function verifyP256(
  jwkText: string,
  value: string,
  signature: string
): Promise<boolean> {
  try {
    const key = await importP256Key(jwkText, ["verify"]);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      base64urlToBytes(signature),
      new TextEncoder().encode(value)
    );
  } catch {
    return false;
  }
}

function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + padding;
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function stableJson(value: unknown): string {
  return JSON.stringify(value);
}

function dmzRequestSigningPayload(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string
): Promise<string> {
  return sha256(body).then((bodyHash) =>
    [method.toUpperCase(), path, timestamp, nonce, bodyHash].join("\n")
  );
}

function grantSigningPayload(grant: {
  iss: string;
  aud: string;
  grantId: string;
  devicePublicKey: JsonWebKey;
  issuedAt: number;
  expiresAt: number;
}): string {
  return stableJson(grant);
}

function getSessionToken(request: Request): string | null {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  for (const part of cookie.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === SESSION_COOKIE) return valueParts.join("=") || null;
  }

  return null;
}

async function getSession(request: Request, env: Bindings) {
  const token = getSessionToken(request);
  if (!token) return null;

  const tokenHash = await sha256(token);
  const session = await env.DB.prepare(
    `SELECT id, stage, expires_at, last_seen_at
     FROM sessions
     WHERE token_hash = ?
     LIMIT 1`
  )
    .bind(tokenHash)
    .first<{ id: string; stage: SessionStage; expires_at: number; last_seen_at: number }>();

  if (!session) return null;

  const now = Date.now();

  if (session.expires_at <= now || session.last_seen_at + SESSION_LEASE_MS <= now) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?")
      .bind(session.id)
      .run();
    return null;
  }

  return session;
}

async function createSession(env: Bindings, stage: SessionStage) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO sessions
      (id, token_hash, stage, created_at, expires_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(id, tokenHash, stage, now, now + SESSION_TTL_MS, now)
    .run();

  return { token, id };
}

async function createHandoff(env: Bindings, sessionId: string) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const id = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO handoffs
      (id, token_hash, session_id, created_at, expires_at, used_at)
     VALUES (?, ?, ?, ?, ?, NULL)`
  )
    .bind(id, tokenHash, sessionId, now, now + HANDOFF_TTL_MS)
    .run();

  return { token, id };
}

function sessionCookie(token: string): string {
  return [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    "Domain=.tyleros.uk",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ].join("; ");
}

function handoffCookie(token: string): string {
  return [
    `${HANDOFF_COOKIE}=${token}`,
    "Path=/",
    "Domain=.tyleros.uk",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${Math.floor(HANDOFF_TTL_MS / 1000)}`,
  ].join("; ");
}

function clearHandoffCookie(): string {
  return [
    `${HANDOFF_COOKIE}=`,
    "Path=/",
    "Domain=.tyleros.uk",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

function getHandoffToken(request: Request): string | null {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  for (const part of cookie.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === HANDOFF_COOKIE) return valueParts.join("=") || null;
  }

  return null;
}

function clearSessionCookie(): string {
  return [
    `${SESSION_COOKIE}=`,
    "Path=/",
    "Domain=.tyleros.uk",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}


async function verifyDmzServiceRequest(
  request: Request,
  env: Bindings,
  body: string
): Promise<boolean> {
  if (!env.DMZ_SERVICE_PUBLIC_KEY_JWK) return false;

  const timestamp = request.headers.get("X-TylerOS-DMZ-Timestamp");
  const nonce = request.headers.get("X-TylerOS-DMZ-Nonce");
  const signature = request.headers.get("X-TylerOS-DMZ-Signature");

  if (!timestamp || !nonce || !signature) return false;

  const timestampMs = Number(timestamp);
  if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > DMZ_REQUEST_SKEW_MS) {
    return false;
  }

  const payload = await dmzRequestSigningPayload(
    request.method,
    new URL(request.url).pathname,
    timestamp,
    nonce,
    body
  );

  const valid = await verifyP256(
    env.DMZ_SERVICE_PUBLIC_KEY_JWK,
    payload,
    signature
  );

  if (!valid) return false;

  const nonceResult = await env.DB.prepare(
    `INSERT INTO dmz_request_nonces (nonce, expires_at)
     VALUES (?, ?)
     ON CONFLICT(nonce) DO NOTHING`
  )
    .bind(nonce, Date.now() + DMZ_REQUEST_SKEW_MS)
    .run();

  return nonceResult.meta.changes === 1;
}

function authRedirect(): Response {
  return Response.redirect("https://auth.tyleros.uk/", 302);
}

async function verifyTurnstile(
  token: unknown,
  request: Request,
  env: Bindings
): Promise<boolean> {
  if (typeof token !== "string" || token.length === 0) return false;

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token,
          remoteip: request.headers.get("CF-Connecting-IP") ?? "",
        }),
      }
    );

    if (!response.ok) return false;

    const result = await response.json() as {
      success?: boolean;
      action?: string;
      hostname?: string;
    };

    return (
      result.success === true &&
      result.action === "login" &&
      result.hostname === "auth.tyleros.uk"
    );
  } catch (error) {
    console.error("Turnstile verification error:", error);
    return false;
  }
}

app.get("/api/config", (c) =>
  c.json({ turnstileSiteKey: c.env.TURNSTILE_SITE_KEY })
);

app.post("/api/login/options", async (c) => {
  const body = await c.req.json<{ turnstileToken?: string }>();

  if (!(await verifyTurnstile(body.turnstileToken, c.req.raw, c.env))) {
    return c.json({ error: "Human verification failed." }, 403);
  }

  const credential = await c.env.DB.prepare(
    `SELECT credential_id, transports
     FROM webauthn_credentials
     ORDER BY created_at ASC
     LIMIT 1`
  ).first<{ credential_id: string; transports: string | null }>();

  if (!credential) {
    return c.json({ error: "No TylerOS passkey has been registered." }, 404);
  }

  const options = await generateAuthenticationOptions({
    rpID: c.env.RP_ID,
    userVerification: "required",
    allowCredentials: [
      {
        id: credential.credential_id,
        transports: credential.transports
          ? JSON.parse(credential.transports)
          : undefined,
      },
    ],
  });

  const challengeId = crypto.randomUUID();
  const now = Date.now();

  await c.env.DB.prepare(
    `INSERT INTO auth_challenges
      (id, challenge, type, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(
      challengeId,
      options.challenge,
      "authentication",
      now + 5 * 60 * 1000,
      now
    )
    .run();

  return c.json({ challengeId, options });
});

app.post("/api/login/verify", async (c) => {
  try {
    const body = await c.req.json<{
      challengeId: string;
      response: AuthenticationResponseJSON;
    }>();

    const challenge = await c.env.DB.prepare(
      `SELECT challenge, expires_at
       FROM auth_challenges
       WHERE id = ? AND type = ?`
    )
      .bind(body.challengeId, "authentication")
      .first<{ challenge: string; expires_at: number }>();

    if (!challenge) {
      return c.json({ error: "Authentication challenge not found." }, 400);
    }

    if (challenge.expires_at < Date.now()) {
      await c.env.DB.prepare("DELETE FROM auth_challenges WHERE id = ?")
        .bind(body.challengeId)
        .run();
      return c.json({ error: "Authentication challenge expired." }, 400);
    }

    const credential = await c.env.DB.prepare(
      `SELECT credential_id, public_key, counter, transports
       FROM webauthn_credentials
       WHERE credential_id = ?`
    )
      .bind(body.response.id)
      .first<{
        credential_id: string;
        public_key: ArrayBuffer;
        counter: number;
        transports: string | null;
      }>();

    if (!credential) {
      return c.json({ error: "Passkey not recognised." }, 401);
    }

    let verification: VerifiedAuthenticationResponse;

    try {
      // D1's ArrayBuffer typing can be ArrayBufferLike under newer Workers types.
      // Copy it into a concrete ArrayBuffer before giving it to SimpleWebAuthn.
      const storedPublicKey = new Uint8Array(credential.public_key);
      const publicKeyBuffer = new ArrayBuffer(storedPublicKey.byteLength);
      new Uint8Array(publicKeyBuffer).set(storedPublicKey);

      let transports: any[] | undefined;
      if (credential.transports) {
        try {
          const parsed = JSON.parse(credential.transports);
          if (Array.isArray(parsed)) {
            transports = parsed as AuthenticatorTransport[];
          }
        } catch (error) {
          console.error("Stored WebAuthn transports JSON is invalid:", error);
          return c.json({
            error: "Stored passkey transport data is invalid.",
            code: "WEBAUTHN_TRANSPORTS_ERROR",
          }, 500);
        }
      }

      verification = await verifyAuthenticationResponse({
        response: body.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: c.env.ORIGIN,
        expectedRPID: c.env.RP_ID,
        requireUserVerification: true,
        credential: {
          id: credential.credential_id,
          publicKey: new Uint8Array(publicKeyBuffer),
          counter: credential.counter,
          transports,
        },
      });
    } catch (error) {
      console.error("WebAuthn authentication error:", error);
      const message = error instanceof Error ? error.message : String(error);
      return c.json({
        error: `Passkey verification failed: ${message}`,
        code: "WEBAUTHN_VERIFY_ERROR",
      }, 401);
    }

    if (!verification.verified) {
      return c.json({ error: "Passkey verification failed." }, 401);
    }

    try {
      await c.env.DB.prepare("DELETE FROM auth_challenges WHERE id = ?")
        .bind(body.challengeId)
        .run();

      await c.env.DB.prepare(
        `UPDATE webauthn_credentials
         SET counter = ?
         WHERE credential_id = ?`
      )
        .bind(
          verification.authenticationInfo.newCounter,
          credential.credential_id
        )
        .run();

      const session = await createSession(c.env, "cf");
      const handoff = await createHandoff(c.env, session.id);

      return c.json({
        verified: true,
        setCookie: sessionCookie(session.token),
      }, {
        headers: [
          ["Set-Cookie", sessionCookie(session.token)],
          ["Set-Cookie", handoffCookie(handoff.token)],
        ],
      });
    } catch (error) {
      console.error("Authentication session persistence error:", error);
      const message = error instanceof Error ? error.message : String(error);
      return c.json({
        error: `Authentication succeeded but the session could not be created: ${message}`,
        code: "AUTH_SESSION_ERROR",
      }, 500);
    }
  } catch (error) {
    console.error("Authentication verification route error:", error);
    const message = error instanceof Error ? error.message : String(error);
    return c.json({
      error: `Authentication verification internal error: ${message}`,
      code: "AUTH_VERIFY_INTERNAL_ERROR",
    }, 500);
  }
});

app.post("/api/logout", async (c) => {
  const token = getSessionToken(c.req.raw);
  if (token) {
    const tokenHash = await sha256(token);
    await c.env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
  }

  return c.json({ loggedOut: true }, {
    headers: { "Set-Cookie": clearSessionCookie() },
  });
});

app.get("/api/session", async (c) => {
  const session = await getSession(c.req.raw, c.env);
  return c.json({
    authenticated: Boolean(session),
    stage: session?.stage ?? null,
  });
});

app.post("/api/heartbeat", async (c) => {
  const token = getSessionToken(c.req.raw);
  if (!token) {
    return c.json({
      alive: false,
      authenticated: false,
      code: "AUTH_REQUIRED",
    }, 401);
  }

  const tokenHash = await sha256(token);
  const session = await c.env.DB.prepare(
    `SELECT id, stage, expires_at, last_seen_at
     FROM sessions
     WHERE token_hash = ?
     LIMIT 1`
  )
    .bind(tokenHash)
    .first<{
      id: string;
      stage: SessionStage;
      expires_at: number;
      last_seen_at: number;
    }>();

  const now = Date.now();

  if (
    !session ||
    session.expires_at <= now ||
    session.last_seen_at + SESSION_LEASE_MS <= now
  ) {
    if (session) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?")
        .bind(session.id)
        .run();
    }

    return c.json({
      alive: false,
      authenticated: false,
      code: "AUTH_LEASE_EXPIRED",
    }, 401, {
      "Set-Cookie": clearSessionCookie(),
    });
  }

  // Ignore accidental duplicate heartbeats arriving too quickly.
  if (now - session.last_seen_at >= HEARTBEAT_MIN_INTERVAL_MS) {
    await c.env.DB.prepare(
      `UPDATE sessions
       SET last_seen_at = ?
       WHERE id = ?`
    )
      .bind(now, session.id)
      .run();
  }

  return c.json({
    alive: true,
    authenticated: true,
    stage: session.stage,
    expiresAt: session.expires_at,
    leaseExpiresAt: now + SESSION_LEASE_MS,
  });
});

app.get("/api/dmz/status", async (c) => {
  const session = await getSession(c.req.raw, c.env);

  if (!session || session.stage !== "cf") {
    return c.json({
      connected: false,
      authenticated: false,
      code: "CF_AUTH_REQUIRED",
    }, 401);
  }

  const handoffToken = getHandoffToken(c.req.raw);
  if (!handoffToken) {
    return c.json({
      connected: false,
      authenticated: true,
      code: "DMZ_HANDOFF_NOT_AVAILABLE",
      message: "The DMZ handoff is not available. Please authenticate again.",
    }, 409);
  }

  const tokenHash = await sha256(handoffToken);
  const handoff = await c.env.DB.prepare(
    `SELECT id, session_id, expires_at, used_at
     FROM handoffs
     WHERE token_hash = ?
     LIMIT 1`
  )
    .bind(tokenHash)
    .first<{
      id: string;
      session_id: string;
      expires_at: number;
      used_at: number | null;
    }>();

  if (
    !handoff ||
    handoff.session_id !== session.id ||
    handoff.used_at !== null ||
    handoff.expires_at <= Date.now()
  ) {
    return c.json({
      connected: false,
      authenticated: true,
      code: "DMZ_HANDOFF_INVALID",
      message: "The DMZ handoff is invalid or has expired. Please authenticate again.",
    }, 409, {
      "Set-Cookie": clearHandoffCookie(),
    });
  }

  return c.json({
    connected: true,
    authenticated: true,
    tunnel: true,
    dmz: false,
    stage: "cf",
    handoffUrl: `https://dmz.tyleros.uk/userauth?handoff=${encodeURIComponent(handoffToken)}`,
    handoffExpiresAt: handoff.expires_at,
  }, {
    headers: {
      "Set-Cookie": clearHandoffCookie(),
    },
  });
});

app.post("/api/dmz/device/authorize", async (c) => {
  const bodyText = await c.req.text();

  if (!(await verifyDmzServiceRequest(c.req.raw, c.env, bodyText))) {
    return c.json({
      authorized: false,
      code: "DMZ_SERVICE_UNAUTHORISED",
    }, 401);
  }

  let body: {
    handoffToken?: string;
    devicePublicKey?: JsonWebKey;
  };

  try {
    body = JSON.parse(bodyText);
  } catch {
    return c.json({
      authorized: false,
      code: "INVALID_REQUEST",
    }, 400);
  }

  if (
    typeof body.handoffToken !== "string" ||
    !body.handoffToken ||
    !body.devicePublicKey ||
    body.devicePublicKey.kty !== "EC" ||
    body.devicePublicKey.crv !== "P-256" ||
    typeof body.devicePublicKey.x !== "string" ||
    typeof body.devicePublicKey.y !== "string"
  ) {
    return c.json({
      authorized: false,
      code: "DEVICE_KEY_REQUIRED",
    }, 400);
  }

  const handoffHash = await sha256(body.handoffToken);
  const now = Date.now();

  const handoff = await c.env.DB.prepare(
    `SELECT id, session_id, expires_at, used_at
     FROM handoffs
     WHERE token_hash = ?
     LIMIT 1`
  )
    .bind(handoffHash)
    .first<{
      id: string;
      session_id: string;
      expires_at: number;
      used_at: number | null;
    }>();

  if (
    !handoff ||
    handoff.used_at !== null ||
    handoff.expires_at <= now
  ) {
    return c.json({
      authorized: false,
      code: "HANDOFF_INVALID",
    }, 401);
  }

  const session = await c.env.DB.prepare(
    `SELECT id, stage, expires_at, last_seen_at
     FROM sessions
     WHERE id = ?
     LIMIT 1`
  )
    .bind(handoff.session_id)
    .first<{
      id: string;
      stage: SessionStage;
      expires_at: number;
      last_seen_at: number;
    }>();

  if (
    !session ||
    session.stage !== "cf" ||
    session.expires_at <= now ||
    session.last_seen_at + SESSION_LEASE_MS <= now
  ) {
    return c.json({
      authorized: false,
      code: "CF_SESSION_EXPIRED",
    }, 401);
  }

  const grantId = crypto.randomUUID();
  const issuedAt = now;
  const expiresAt = now + DMZ_GRANT_TTL_MS;

  const grant = {
    iss: "auth.tyleros.uk",
    aud: "tyleros-dmz",
    grantId,
    devicePublicKey: body.devicePublicKey,
    issuedAt,
    expiresAt,
  };

  const grantPayload = grantSigningPayload(grant);

  if (!c.env.DMZ_SIGNING_PRIVATE_KEY_JWK) {
    return c.json({
      authorized: false,
      code: "DMZ_SIGNING_KEY_NOT_CONFIGURED",
    }, 503);
  }

  let signature: string;
  try {
    signature = await signP256(
      c.env.DMZ_SIGNING_PRIVATE_KEY_JWK,
      grantPayload
    );
  } catch (error) {
    console.error("DMZ grant signing error:", error);
    return c.json({
      authorized: false,
      code: "DMZ_SIGNING_ERROR",
    }, 500);
  }

  await c.env.DB.prepare(
    `INSERT INTO dmz_grants
      (id, session_id, handoff_id, device_public_key, created_at, expires_at, used_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL)`
  )
    .bind(
      grantId,
      session.id,
      handoff.id,
      JSON.stringify(body.devicePublicKey),
      issuedAt,
      expiresAt
    )
    .run();

  return c.json({
    authorized: true,
    grant: {
      ...grant,
      signature,
    },
  });
});

app.post("/api/dmz/grant/consume", async (c) => {
  const bodyText = await c.req.text();

  if (!(await verifyDmzServiceRequest(c.req.raw, c.env, bodyText))) {
    return c.json({
      consumed: false,
      code: "DMZ_SERVICE_UNAUTHORISED",
    }, 401);
  }

  let body: { grantId?: string };

  try {
    body = JSON.parse(bodyText);
  } catch {
    return c.json({
      consumed: false,
      code: "INVALID_REQUEST",
    }, 400);
  }

  if (typeof body.grantId !== "string" || !body.grantId) {
    return c.json({
      consumed: false,
      code: "GRANT_REQUIRED",
    }, 400);
  }

  const now = Date.now();

  const grant = await c.env.DB.prepare(
    `SELECT id, session_id, expires_at, used_at
     FROM dmz_grants
     WHERE id = ?
     LIMIT 1`
  )
    .bind(body.grantId)
    .first<{
      id: string;
      session_id: string;
      expires_at: number;
      used_at: number | null;
    }>();

  if (!grant || grant.used_at !== null || grant.expires_at <= now) {
    return c.json({
      consumed: false,
      code: "GRANT_INVALID",
    }, 401);
  }

  const session = await c.env.DB.prepare(
    `SELECT id, stage, expires_at, last_seen_at
     FROM sessions
     WHERE id = ?
     LIMIT 1`
  )
    .bind(grant.session_id)
    .first<{
      id: string;
      stage: SessionStage;
      expires_at: number;
      last_seen_at: number;
    }>();

  if (
    !session ||
    session.stage !== "cf" ||
    session.expires_at <= now ||
    session.last_seen_at + SESSION_LEASE_MS <= now
  ) {
    return c.json({
      consumed: false,
      code: "CF_SESSION_EXPIRED",
    }, 401);
  }

  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE dmz_grants
       SET used_at = ?
       WHERE id = ?
         AND used_at IS NULL
         AND expires_at > ?`
    ).bind(now, grant.id, now),
    c.env.DB.prepare(
      `UPDATE sessions
       SET stage = ?, last_seen_at = ?
       WHERE id = ? AND stage = ?`
    ).bind("dmz", now, session.id, "cf"),
  ]);

  if (
    results.length !== 2 ||
    results[0].meta.changes !== 1 ||
    results[1].meta.changes !== 1
  ) {
    return c.json({
      consumed: false,
      code: "GRANT_ALREADY_USED",
    }, 409);
  }

  return c.json({
    consumed: true,
    stage: "dmz",
    expiresAt: session.expires_at,
  });
});

const TRANSIT_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <title>TylerOS — Connecting</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #111; color: #f5f5f5; font-family: system-ui, sans-serif; }
    .card { width: min(520px, calc(100% - 40px)); padding: 32px; border: 1px solid #333; border-radius: 16px; background: #181818; box-sizing: border-box; }
    .brand { font-weight: 700; font-size: 24px; margin-bottom: 28px; }
    h1 { font-size: 22px; margin: 0 0 12px; }
    .status { color: #bbb; line-height: 1.5; }
    .steps { display: grid; gap: 12px; margin: 24px 0; }
    .step { display: flex; gap: 12px; align-items: center; color: #888; }
    .step.complete, .step.active { color: #f5f5f5; }
    .icon { width: 24px; text-align: center; }
    .spinner { width: 22px; height: 22px; margin: 20px 0; border: 3px solid #444; border-top-color: #fff; border-radius: 50%; animation: spin .8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .error { margin-top: 20px; padding: 14px; border: 1px solid #633; border-radius: 10px; background: #241414; }
    .code { font-family: monospace; font-weight: 700; margin-bottom: 6px; }
    button { margin-top: 18px; padding: 10px 16px; border: 0; border-radius: 8px; cursor: pointer; }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">TylerOS</div>
    <section aria-live="polite">
      <h1 id="title">Connecting to TylerOS</h1>
      <div class="steps">
        <div class="step complete"><span class="icon">✓</span><span>Authentication</span></div>
        <div class="step active" id="dmzStep"><span class="icon" id="dmzIcon">◌</span><span id="dmzLabel">Checking DMZ</span></div>
        <div class="step" id="serverStep"><span class="icon">○</span><span>TylerOS server</span></div>
      </div>
      <div class="spinner" id="spinner"></div>
      <p class="status" id="status">Checking whether the DMZ is reachable…</p>
      <div class="error" id="error" hidden>
        <div class="code" id="errorCode"></div>
        <div id="errorMessage"></div>
      </div>
      <button id="retryButton" hidden>Try again</button>
    </section>
  </main>
  <script>
    const DMZ_URL = "https://dmz.tyleros.uk/userauth";
    const TIMEOUT_MS = 6000;
    const title = document.getElementById("title");
    const status = document.getElementById("status");
    const spinner = document.getElementById("spinner");
    const error = document.getElementById("error");
    const errorCode = document.getElementById("errorCode");
    const errorMessage = document.getElementById("errorMessage");
    const retryButton = document.getElementById("retryButton");
    const dmzStep = document.getElementById("dmzStep");
    const dmzIcon = document.getElementById("dmzIcon");
    const dmzLabel = document.getElementById("dmzLabel");

    function fail(code, message) {
      spinner.hidden = true;
      title.textContent = "Unable to continue";
      status.textContent = "Your TylerOS authentication is valid, but the DMZ could not be reached.";
      errorCode.textContent = code;
      errorMessage.textContent = message;
      error.hidden = false;
      retryButton.hidden = false;
      dmzStep.className = "step";
      dmzIcon.textContent = "✕";
      dmzLabel.textContent = "DMZ unreachable";
    }

    retryButton.addEventListener("click", () => location.reload());

    async function checkDmz() {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
      try {
        // no-cors deliberately tests network reachability without requiring the DMZ
        // service to expose CORS headers to tyleros.uk. Any network response means
        // the DMZ endpoint is reachable; a network failure means it is not.
        await fetch(DMZ_URL, { mode: "no-cors", cache: "no-store", signal: controller.signal });
        return true;
      } finally {
        clearTimeout(timer);
      }
    }

    async function start() {
      try {
        const sessionResponse = await fetch("/api/session", { cache: "no-store", headers: { Accept: "application/json" } });
        const session = await sessionResponse.json();

        if (!sessionResponse.ok || !session.authenticated) {
          location.replace("https://auth.tyleros.uk/");
          return;
        }

        dmzStep.className = "step active";
        dmzIcon.textContent = "◌";
        dmzLabel.textContent = "Checking DMZ";
        status.textContent = "Checking whether the DMZ is reachable…";

        await checkDmz();

        const handoffResponse = await fetch("/api/dmz/status", {
          method: "GET",
          cache: "no-store",
          headers: { Accept: "application/json" }
        });
        const handoff = await handoffResponse.json().catch(() => ({}));

        if (!handoffResponse.ok || !handoff.handoffUrl) {
          throw new Error(
            handoff.message || "A valid DMZ handoff could not be created."
          );
        }

        dmzStep.className = "step complete";
        dmzIcon.textContent = "✓";
        dmzLabel.textContent = "DMZ reachable";
        title.textContent = "DMZ connected";
        status.textContent = "Redirecting to DMZ authentication…";
        location.replace(handoff.handoffUrl);
      } catch (e) {
        if (e?.name === "AbortError") {
          fail("DMZ_TIMEOUT", "The DMZ did not respond within 6 seconds. The tunnel may be offline.");
        } else {
          fail("DMZ_UNREACHABLE", "The DMZ could not be reached. You can retry when the tunnel is available.");
        }
      }
    }

    start();
  </script>
</body>
</html>`;

app.get("/transit", async (c) => {
  const session = await getSession(c.req.raw, c.env);

  if (!session) {
    return authRedirect();
  }

  return new Response(TRANSIT_HTML, {
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" },
  });
});

app.all("*", async (c) => {
  const hostname = new URL(c.req.url).hostname;

  if (hostname === "auth.tyleros.uk") {
    return c.env.ASSETS.fetch(c.req.raw);
  }

  if (hostname === "tyleros.uk") {
    const session = await getSession(c.req.raw, c.env);

    if (!session) {
      return authRedirect();
    }

    if (session.stage !== "dmz") {
      return Response.redirect(new URL("/transit", c.req.url).toString(), 302);
    }

    // Once the DMZ device-proof stage is complete, tyleros.uk becomes
    // the public application entrypoint. Keep the Worker as the gatekeeper,
    // then route the authenticated request privately through Workers VPC
    // to the DMZ gateway. The VPC Service target is fixed by Cloudflare;
    // the request URL supplies the Host/path that the DMZ gateway sees.
    try {
      return await c.env.DMZ.fetch(c.req.raw);
    } catch (error) {
      console.error("DMZ VPC request failed:", error);
      return c.json({
        error: "TylerOS DMZ is unavailable.",
        code: "DMZ_VPC_UNAVAILABLE",
      }, 503);
    }
  }

  return c.json({ error: "Unknown TylerOS hostname." }, 404);
});

export default app;

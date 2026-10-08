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
};

type SessionStage = "cf" | "dmz";

const app = new Hono<{ Bindings: Bindings }>();

const SESSION_COOKIE = "tyleros_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_LEASE_MS = 15 * 1000;
const HEARTBEAT_MIN_INTERVAL_MS = 3 * 1000;
const HANDOFF_TTL_MS = 2 * 60 * 1000;

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

  return token;
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

function safeReturnPath(value: string | null): string {
  if (!value) return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function authRedirect(returnPath: string): Response {
  const url = new URL("https://auth.tyleros.uk/");
  url.searchParams.set("return", returnPath);
  return Response.redirect(url.toString(), 302);
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
  const body = await c.req.json<{
    challengeId: string;
    response: AuthenticationResponseJSON;
    returnPath?: string;
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
    // D1/Cloudflare types can expose ArrayBufferLike here. SimpleWebAuthn
    // requires a Uint8Array backed by a concrete ArrayBuffer. Copy the key
    // into a fresh ArrayBuffer so the TypeScript and runtime types agree.
    const storedPublicKey = new Uint8Array(credential.public_key);
    const publicKeyBuffer = new ArrayBuffer(storedPublicKey.byteLength);
    new Uint8Array(publicKeyBuffer).set(storedPublicKey);

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
        transports: credential.transports
          ? JSON.parse(credential.transports)
          : undefined,
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

  await c.env.DB.prepare("DELETE FROM auth_challenges WHERE id = ?")
    .bind(body.challengeId)
    .run();

  if (!verification.verified) {
    return c.json({ error: "Passkey verification failed." }, 401);
  }

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

  const token = await createSession(c.env, "cf");

  return c.json({
    verified: true,
    returnPath: safeReturnPath(body.returnPath ?? null),
    setCookie: sessionCookie(token),
  }, {
    headers: {
      "Set-Cookie": sessionCookie(token),
    },
  });
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

  if (!session || (session.stage !== "cf" && session.stage !== "dmz")) {
    return c.json({
      connected: false,
      authenticated: false,
      code: "CF_AUTH_REQUIRED",
    }, 401);
  }

  if (session.stage === "dmz") {
    return c.json({
      connected: true,
      authenticated: true,
      tunnel: true,
      dmz: true,
      stage: "dmz",
    });
  }

  if (!c.env.DMZ_ORIGIN) {
    return c.json({
      connected: false,
      authenticated: false,
      tunnel: false,
      code: "DMZ_ORIGIN_NOT_CONFIGURED",
      message: "The Cloudflare-to-DMZ origin has not been configured yet.",
    }, 503);
  }

  try {
    const origin = new URL(c.env.DMZ_ORIGIN);
    const target = new URL("/health", origin);

    const response = await fetch(new Request(target.toString(), {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "X-TylerOS-Gateway": "tyleros-gateway",
      },
    }));

    if (!response.ok) {
      return c.json({
        connected: false,
        authenticated: false,
        tunnel: false,
        code: `DMZ_HTTP_${response.status}`,
        message: "The DMZ origin returned an error.",
      }, 502);
    }

    const dmzToken = await createSession(c.env, "dmz");

    return c.json({
      connected: true,
      authenticated: true,
      tunnel: true,
      dmz: true,
      stage: "dmz",
    }, {
      headers: {
        "Set-Cookie": sessionCookie(dmzToken),
      },
    });
  } catch (error) {
    console.error("DMZ connection error:", error);
    return c.json({
      connected: false,
      authenticated: false,
      tunnel: false,
      code: "DMZ_CONNECTION_FAILED",
      message: "The DMZ connection could not be established.",
    }, 502);
  }
});

app.get("/dmz/ingress", async (c) => {
  const session = await getSession(c.req.raw, c.env);

  if (!session) {
    return authRedirect("/dmz/ingress");
  }

  const ingress = new URL(c.req.url);
  ingress.pathname = "/dmz-ingress.html";
  return c.env.ASSETS.fetch(new Request(ingress.toString(), c.req.raw));
});

app.all("*", async (c) => {
  const hostname = new URL(c.req.url).hostname;

  if (hostname === "auth.tyleros.uk") {
    return c.env.ASSETS.fetch(c.req.raw);
  }

  if (hostname === "tyleros.uk") {
    const session = await getSession(c.req.raw, c.env);

    if (!session) {
      return authRedirect(new URL(c.req.url).pathname + new URL(c.req.url).search);
    }

    if (session.stage !== "dmz") {
      const target = new URL("/dmz/ingress", c.req.url);
      target.searchParams.set(
        "return",
        new URL(c.req.url).pathname + new URL(c.req.url).search
      );
      return Response.redirect(target.toString(), 302);
    }

    return c.env.ASSETS.fetch(c.req.raw);
  }

  return c.json({ error: "Unknown TylerOS hostname." }, 404);
});

export default app;

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

      const token = await createSession(c.env, "cf");

      return c.json({
        verified: true,
        setCookie: sessionCookie(token),
      }, {
        headers: {
          "Set-Cookie": sessionCookie(token),
        },
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

        dmzStep.className = "step complete";
        dmzIcon.textContent = "✓";
        dmzLabel.textContent = "DMZ reachable";
        title.textContent = "DMZ connected";
        status.textContent = "Redirecting to DMZ authentication…";
        location.replace(DMZ_URL);
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

    return c.env.ASSETS.fetch(c.req.raw);
  }

  return c.json({ error: "Unknown TylerOS hostname." }, 404);
});

export default app;

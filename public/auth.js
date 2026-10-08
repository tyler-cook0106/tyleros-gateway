const loginButton = document.getElementById("loginButton");
const status = document.getElementById("status");
const turnstileElement = document.getElementById("turnstile");

let turnstileToken = null;
let turnstileWidgetId = null;
let turnstileAutoRetryUsed = false;
let turnstileResetTimer = null;


function setStatus(message, type = "") {
  status.textContent = message;
  status.className = `status ${type}`;
}

window.onTurnstileSuccess = (token) => {
  turnstileToken = token;
  turnstileAutoRetryUsed = false;
  loginButton.disabled = false;
  setStatus("Human verification complete.");
};

window.onTurnstileExpired = () => {
  turnstileToken = null;
  loginButton.disabled = true;
  setStatus("Human verification expired.", "error");
};

window.onTurnstileError = () => {
  turnstileToken = null;
  loginButton.disabled = true;

  if (!turnstileAutoRetryUsed && window.turnstile && turnstileWidgetId !== null) {
    turnstileAutoRetryUsed = true;
    setStatus("Retrying human verification…");

    if (turnstileResetTimer) clearTimeout(turnstileResetTimer);
    turnstileResetTimer = setTimeout(() => {
      try {
        window.turnstile.reset(turnstileWidgetId);
      } catch (error) {
        console.error("Turnstile reset error:", error);
        setStatus("Human verification could not be completed. Try again.", "error");
      }
    }, 250);
    return;
  }

  setStatus("Human verification could not be completed. Try again.", "error");
};

function base64urlToUint8Array(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("Expected a non-empty base64url string.");
  }

  // WebAuthn IDs/challenges are base64url. Reject malformed values here so
  // the browser does not surface a vague DOMException such as
  // “String did not match the expected pattern.”
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Invalid base64url WebAuthn value.");
  }

  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function buildWebAuthnRequestOptions(options) {
  if (!options || typeof options !== "object") {
    throw new TypeError("Authentication options were not returned.");
  }

  // Modern Chromium/Edge implement the WebAuthn JSON conversion helpers.
  // Let the browser perform the standards-defined conversion rather than
  // constructing BufferSource values by hand.
  if (typeof PublicKeyCredential !== "undefined" &&
      typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
    return PublicKeyCredential.parseRequestOptionsFromJSON(options);
  }

  const publicKey = {
    ...options,
    challenge: base64urlToUint8Array(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: base64urlToUint8Array(credential.id),
    })),
  };

  if (options.rpId && typeof options.rpId !== "string") {
    throw new TypeError("Invalid WebAuthn RP ID.");
  }

  return publicKey;
}

function uint8ArrayToBase64url(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function serializeCredential(credential) {
  return {
    id: credential.id,
    rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    response: {
      clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
      authenticatorData: uint8ArrayToBase64url(new Uint8Array(credential.response.authenticatorData)),
      signature: uint8ArrayToBase64url(new Uint8Array(credential.response.signature)),
      userHandle: credential.response.userHandle
        ? uint8ArrayToBase64url(new Uint8Array(credential.response.userHandle))
        : null
    }
  };
}


async function readJsonResponse(response, label) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch (error) {
    console.error(`${label} returned non-JSON`, { status: response.status, contentType: response.headers.get("content-type"), body: text.slice(0, 500) }, error);
    throw new Error(`${label} returned an invalid response.`);
  }
}

async function initialiseTurnstile() {
  if (!window.turnstile) {
    setTimeout(initialiseTurnstile, 100);
    return;
  }

  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const config = await readJsonResponse(response, "TylerOS configuration");

    if (!config.turnstileSiteKey) {
      setStatus("Turnstile site key is not configured.", "error");
      return;
    }

    turnstileWidgetId = window.turnstile.render(turnstileElement, {
      sitekey: config.turnstileSiteKey,
      action: "login",
      appearance: "interaction-only",
      callback: window.onTurnstileSuccess,
      "expired-callback": window.onTurnstileExpired,
      "error-callback": window.onTurnstileError
    });
  } catch (error) {
    console.error(error);
    setStatus("Could not initialise human verification.", "error");
  }
}

loginButton.addEventListener("click", async () => {
  if (!turnstileToken) return;

  loginButton.disabled = true;
  setStatus("Checking passkey…");

  try {
    const optionsResponse = await fetch("/api/login/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ turnstileToken })
    });

    const optionsData = await readJsonResponse(optionsResponse, "Authentication options");

    if (!optionsResponse.ok) {
      throw new Error(optionsData.error || "Could not start authentication.");
    }

    let publicKey;
    try {
      publicKey = buildWebAuthnRequestOptions(optionsData.options);
    } catch (error) {
      console.error("Invalid WebAuthn authentication options:", optionsData.options, error);
      throw new Error("The passkey authentication request was invalid. Please try again.");
    }

    let credential;
    try {
      credential = await navigator.credentials.get({ publicKey });
    } catch (error) {
      console.error("WebAuthn browser request failed:", error);

      if (error?.name === "NotAllowedError") {
        throw new Error("Passkey authentication was cancelled or not completed.");
      }

      if (error?.name === "SecurityError") {
        throw new Error("This passkey cannot be used from the current TylerOS authentication origin.");
      }

      throw new Error("The passkey authentication request could not be started. Please try again.");
    }

    if (!credential) {
      throw new Error("Passkey authentication was cancelled.");
    }

    const verifyResponse = await fetch("/api/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: optionsData.challengeId,
        response: serializeCredential(credential)
      })
    });

    const result = await readJsonResponse(verifyResponse, "Authentication verification");

    if (!verifyResponse.ok || !result.verified) {
      throw new Error(result.error || "Passkey verification failed.");
    }

    window.location.replace("https://tyleros.uk/transit");
  } catch (error) {
    console.error(error);
    setStatus(error.message || "Something went wrong.", "error");
    turnstileToken = null;
    loginButton.disabled = true;

    if (window.turnstile && turnstileWidgetId !== null) {
      turnstileAutoRetryUsed = false;
      window.turnstile.reset(turnstileWidgetId);
    }
  }
});

initialiseTurnstile();

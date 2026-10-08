const loginButton = document.getElementById("loginButton");
const status = document.getElementById("status");
const turnstileElement = document.getElementById("turnstile");

let turnstileToken = null;
let turnstileWidgetId = null;
let turnstileAutoRetryUsed = false;
let turnstileResetTimer = null;

const params = new URLSearchParams(window.location.search);
const returnPath = params.get("return") || "/";

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
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
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

function safeReturnPath(value) {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

async function initialiseTurnstile() {
  if (!window.turnstile) {
    setTimeout(initialiseTurnstile, 100);
    return;
  }

  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const config = await response.json();

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

    const optionsData = await optionsResponse.json();

    if (!optionsResponse.ok) {
      throw new Error(optionsData.error || "Could not start authentication.");
    }

    const publicKey = {
      ...optionsData.options,
      challenge: base64urlToUint8Array(optionsData.options.challenge),
      allowCredentials: (optionsData.options.allowCredentials || []).map(
        credential => ({
          ...credential,
          id: base64urlToUint8Array(credential.id)
        })
      )
    };

    const credential = await navigator.credentials.get({ publicKey });

    if (!credential) {
      throw new Error("Passkey authentication was cancelled.");
    }

    const verifyResponse = await fetch("/api/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: optionsData.challengeId,
        response: serializeCredential(credential),
        returnPath: safeReturnPath(returnPath)
      })
    });

    const result = await verifyResponse.json();

    if (!verifyResponse.ok || !result.verified) {
      throw new Error(result.error || "Passkey verification failed.");
    }

    const target = new URL("https://tyleros.uk/dmz/ingress");
    target.searchParams.set("return", result.returnPath || safeReturnPath(returnPath));
    window.location.replace(target.toString());
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

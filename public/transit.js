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

const DMZ_URL = "https://dmz.tyleros.uk/userauth";
const PROBE_TIMEOUT_MS = 6000;

function setStep(step, state, icon, label) {
  step.classList.remove("complete", "active", "failed");
  if (state) step.classList.add(state);
  icon.textContent = state === "complete" ? "✓" : state === "failed" ? "✕" : "◌";
  label.textContent = label;
}

function showError(code, message) {
  spinner.style.display = "none";
  title.textContent = "Unable to continue";
  status.textContent = "Your TylerOS authentication is valid, but the DMZ could not be reached.";
  errorCode.textContent = code;
  errorMessage.textContent = message;
  error.hidden = false;
  retryButton.hidden = false;
  setStep(dmzStep, "failed", dmzIcon, dmzLabel);
}

retryButton.addEventListener("click", () => {
  window.location.reload();
});

async function probeDmz() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    const response = await fetch("/api/dmz/status", {
      method: "GET",
      cache: "no-store",
      headers: { "Accept": "application/json" },
      signal: controller.signal
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok || result.connected !== true) {
      const error = new Error(result.message || "The DMZ connection could not be established.");
      error.code = result.code || "DMZ_UNREACHABLE";
      throw error;
    }

    return true;
  } finally {
    clearTimeout(timeout);
  }
}

async function connect() {
  try {
    const response = await fetch("/api/session", {
      method: "GET",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const session = await response.json();

    if (!response.ok || !session.authenticated) {
      window.location.replace("https://auth.tyleros.uk/");
      return;
    }

    setStep(dmzStep, "active", dmzIcon, dmzLabel);
    status.textContent = "Checking the DMZ connection…";

    await probeDmz();

    setStep(dmzStep, "complete", dmzIcon, dmzLabel);
    title.textContent = "DMZ connected";
    status.textContent = "Handing off to DMZ authentication…";

    window.location.replace(DMZ_URL);
  } catch (err) {
    console.error("DMZ transit failed:", err);

    if (err?.name === "AbortError") {
      showError(
        "DMZ_TIMEOUT",
        "The DMZ did not respond within 6 seconds. The tunnel may be offline."
      );
    } else {
      showError(
        err?.code || "DMZ_UNREACHABLE",
        err?.message || "The DMZ tunnel could not be reached. The connection will remain at this stage."
      );
    }
  }
}

connect();

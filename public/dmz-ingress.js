const spinner = document.getElementById("spinner");
const title = document.getElementById("title");
const status = document.getElementById("status");
const error = document.getElementById("error");
const errorCode = document.getElementById("errorCode");
const errorMessage = document.getElementById("errorMessage");
const retryButton = document.getElementById("retryButton");

const params = new URLSearchParams(window.location.search);
const returnPath = params.get("return") || "/";

function showError(code, message) {
  spinner.style.display = "none";
  title.textContent = "Connection failed";
  status.textContent = "The secure path to the DMZ could not be established.";
  errorCode.textContent = code;
  errorMessage.textContent = message;
  error.hidden = false;
  retryButton.hidden = false;
}

retryButton.addEventListener("click", () => {
  window.location.reload();
});

async function connect() {
  try {
    const response = await fetch("/api/dmz/status", {
      method: "GET",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const result = await response.json().catch(() => ({}));

    if (response.status === 401) {
      const auth = new URL("https://auth.tyleros.uk/");
      auth.searchParams.set("return", returnPath);
      window.location.replace(auth.toString());
      return;
    }

    if (!response.ok || !result.connected) {
      showError(
        result.code || `HTTP ${response.status}`,
        result.message || "The DMZ gateway returned an unexpected response."
      );
      return;
    }

    title.textContent = "DMZ Connected";
    status.textContent = "Secure connection established.";

    setTimeout(() => {
      window.location.replace(returnPath.startsWith("/") ? returnPath : "/");
    }, 500);
  } catch (err) {
    console.error(err);
    showError(
      "DMZ_CONNECTION_FAILED",
      "The gateway could not contact the DMZ."
    );
  }
}

connect();

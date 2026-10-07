const title = document.getElementById("title");
const status = document.getElementById("status");
const spinner = document.getElementById("spinner");
const error = document.getElementById("error");
const errorCode = document.getElementById("errorCode");
const errorMessage = document.getElementById("errorMessage");
const retryButton = document.getElementById("retryButton");

async function connect() {
  try {
    const response = await fetch("/api/status", {
      method: "GET",
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    if (data.connected) {
      status.textContent = "Connection established.";
      return;
    }

    throw new Error("Gateway did not establish a connection.");
  } catch (err) {
    spinner.style.display = "none";
    title.textContent = "Connection failed";

    const message = err instanceof Error
      ? err.message
      : "Unknown connection error";

    const match = message.match(/HTTP (\d+)/);

    errorCode.textContent = match
      ? `HTTP ${match[1]}`
      : "ERROR";

    errorMessage.textContent = match
      ? "The DMZ gateway could not be reached."
      : message;

    error.hidden = false;
    retryButton.hidden = false;
  }
}

connect();
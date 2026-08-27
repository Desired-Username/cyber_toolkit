// Shows only the first 4 and last 3 characters; everything else is masked.
// The full key is never re-rendered anywhere after it's been saved.
function maskKey(key) {
  if (key.length <= 7) return "*".repeat(key.length);
  return key.slice(0, 4) + "*".repeat(key.length - 7) + key.slice(-3);
}

// Wires up one service's key card: masked saved view, edit view, save/change/
// remove/cancel actions. Each service card in options.html follows the same
// `<prefix>-saved-view` / `<prefix>-edit-view` / etc. id convention.
function setupKeyCard(prefix, storageKey) {
  const savedView = document.getElementById(`${prefix}-saved-view`);
  const editView = document.getElementById(`${prefix}-edit-view`);
  const maskedEl = document.getElementById(`${prefix}-masked`);
  const input = document.getElementById(`${prefix}-key`);
  const statusEl = document.getElementById(`${prefix}-status`);
  const saveBtn = document.getElementById(`${prefix}-save`);
  const cancelBtn = document.getElementById(`${prefix}-cancel`);
  const changeBtn = document.getElementById(`${prefix}-change`);
  const removeBtn = document.getElementById(`${prefix}-remove`);

  function showSavedView(key) {
    maskedEl.textContent = maskKey(key);
    savedView.hidden = false;
    editView.hidden = true;
    input.value = "";
  }

  function showEditView({ allowCancel }) {
    savedView.hidden = true;
    editView.hidden = false;
    cancelBtn.hidden = !allowCancel;
    input.value = "";
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle("error", Boolean(isError));
    if (message) setTimeout(() => (statusEl.textContent = ""), 2500);
  }

  saveBtn.addEventListener("click", async () => {
    const value = input.value.trim();
    if (!value) {
      setStatus("Enter a key first.", true);
      return;
    }
    await chrome.storage.local.set({ [storageKey]: value });
    input.value = "";
    showSavedView(value);
    setStatus("Saved.");
  });

  changeBtn.addEventListener("click", () => {
    showEditView({ allowCancel: true });
  });

  cancelBtn.addEventListener("click", async () => {
    const stored = await chrome.storage.local.get(storageKey);
    showSavedView(stored[storageKey]);
  });

  removeBtn.addEventListener("click", async () => {
    await chrome.storage.local.remove(storageKey);
    showEditView({ allowCancel: false });
    setStatus("Key removed.");
  });

  chrome.storage.local.get(storageKey).then((stored) => {
    const key = stored[storageKey];
    if (key) showSavedView(key);
    else showEditView({ allowCancel: false });
  });
}

setupKeyCard("vt", "virusTotalApiKey");
setupKeyCard("abuseipdb", "abuseIpDbApiKey");
setupKeyCard("abusech", "abuseChApiKey");
setupKeyCard("greynoise", "greyNoiseApiKey");
setupKeyCard("emailrep", "emailRepApiKey");

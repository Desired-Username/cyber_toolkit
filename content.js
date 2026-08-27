// Keeps the background script informed of what the context menu should be
// built for — the current text selection, or (with no selection) the link
// just right-clicked. This is a fallback for browsers that don't fire
// chrome.contextMenus.onShown (e.g. Vivaldi) — without it, menu titles can
// only be updated at click time, which is too late to affect what the user
// sees before they click.
let lastSent = null;

function report(text) {
  if (text === lastSent) return;
  lastSent = text;
  try {
    // Throws synchronously (not just a promise rejection) if the extension
    // was reloaded/updated since this page loaded its content script.
    chrome.runtime.sendMessage({ type: "cyberToolkitSelection", text }).catch(() => {});
  } catch {
    // Stale script in an old tab; nothing to do until the page is refreshed.
  }
}

function currentSelectionText() {
  return (window.getSelection()?.toString() || "").trim();
}

function reportSelection() {
  report(currentSelectionText());
}

// mailto: links are unwrapped to a bare address so they classify the same
// way a typed-out email address would.
function linkHrefText(link) {
  const href = link.href;
  if (/^mailto:/i.test(href)) return href.replace(/^mailto:/i, "").split("?")[0];
  return href;
}

let debounceHandle = null;
document.addEventListener("selectionchange", () => {
  clearTimeout(debounceHandle);
  debounceHandle = setTimeout(reportSelection, 120);
});
document.addEventListener("mouseup", reportSelection, true);
document.addEventListener("keyup", reportSelection, true);

// Fires immediately before the native context menu appears — the most
// reliable point to capture exactly what's about to be right-clicked.
document.addEventListener(
  "contextmenu",
  (e) => {
    const selection = currentSelectionText();
    if (selection) {
      report(selection);
      return;
    }
    const link = e.target?.closest?.("a[href]");
    if (link) report(linkHrefText(link));
  },
  true
);

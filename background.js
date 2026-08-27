// Service worker: builds a static context menu (every lookup always visible
// for any selection) and runs the relevant fetch when an item is clicked.

const MENU_ROOT = "cyberToolkitRoot";
const MENU_CVE = "lookupCve";
const MENU_IP_PARENT = "ipParent";
const MENU_IP_INFO = "lookupIPInfo";
const MENU_IP_SHODAN = "lookupIPShodan";
const MENU_IP_REPUTATION_PARENT = "ipReputationParent";
const MENU_IP_REPUTATION_VT = "lookupIPReputationVt";
const MENU_IP_REPUTATION_ABUSEIPDB = "lookupIPReputationAbuseIPDB";
const MENU_IP_REPUTATION_GREYNOISE = "lookupIPReputationGreyNoise";
const MENU_IP_REPUTATION_BARRACUDA = "lookupIPReputationBarracuda";
const MENU_IP_REPUTATION_THREATFOX = "lookupIPReputationThreatFox";
const MENU_IP_REPUTATION_ALL = "lookupIPReputationAll";
const MENU_DOMAIN_PARENT = "domainParent";
const MENU_DOMAIN_INFO = "lookupDomainInfo";
const MENU_DOMAIN_CERTS = "lookupDomainCerts";
const MENU_DOMAIN_SSL = "lookupDomainSsl";
const MENU_DOMAIN_WAYBACK = "lookupDomainWayback";
const MENU_DOMAIN_REPUTATION_PARENT = "domainReputationParent";
const MENU_DOMAIN_REPUTATION_VT = "lookupDomainReputationVt";
const MENU_DOMAIN_REPUTATION_URLHAUS = "lookupDomainReputationUrlhaus";
const MENU_DOMAIN_REPUTATION_THREATFOX = "lookupDomainReputationThreatFox";
const MENU_DOMAIN_REPUTATION_ALL = "lookupDomainReputationAll";
const MENU_HASH_PARENT = "hashParent";
const MENU_HASH_VT = "lookupHashVt";
const MENU_HASH_THREATFOX = "lookupHashThreatFox";
const MENU_HASH_MALWAREBAZAAR = "lookupHashMalwareBazaar";
const MENU_HASH_ALL = "lookupHashAll";
const MENU_URL_PARENT = "urlParent";
const MENU_URL_SCAN = "lookupUrlScan";
const MENU_URL_WAYBACK = "lookupUrlWayback";
const MENU_URL_ALL = "lookupUrlAll";
const MENU_EMAIL_PARENT = "emailParent";
const MENU_EMAIL_MXTOOLBOX = "lookupEmailMxtoolbox";
const MENU_EMAIL_EMAILREP = "lookupEmailEmailrep";
const MENU_EMAIL_ALL = "lookupEmailAll";
const MENU_ERRORCODE_PARENT = "errorCodeParent";
const MENU_ERRORCODE_MS = "lookupErrorCodeMs";
const MENU_ERRORCODE_HTTP = "lookupErrorCodeHttp";
const MENU_ERRORCODE_ERRNO = "lookupErrorCodeErrno";
const MENU_ERRORCODE_DB = "lookupErrorCodeDb";

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;
const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
const URL_RE = /^https?:\/\/\S+$/i;
// Loosely matches the shapes error codes tend to take: a hex code (0x...),
// a named constant (ERROR_ACCESS_DENIED, E_FAIL), or a plain decimal number.
// There's no reliable way to tell which *system* a bare code belongs to, so
// this only decides whether to call it an "error code" at all — the specific
// lookup (Microsoft, HTTP, errno, database) is chosen by which menu item the
// user clicks, not by further auto-detection.
const HEX_CODE_RE = /^0x[0-9a-f]+$/i;
const CONSTANT_CODE_RE = /^[A-Z][A-Z0-9_]{2,}$/;
const INTEGER_CODE_RE = /^-?\d{1,10}$/;

function isValidIPv4(text) {
  const m = IPV4_RE.exec(text);
  if (!m) return false;
  return m.slice(1, 5).every((octet) => Number(octet) <= 255);
}

function isValidIPv6(text) {
  return IPV6_RE.test(text) && text.includes(":");
}

function isErrorCode(text) {
  return HEX_CODE_RE.test(text) || CONSTANT_CODE_RE.test(text) || INTEGER_CODE_RE.test(text);
}

// Right-clicking a hyperlink with no active text selection gives us
// info.linkUrl instead of info.selectionText. mailto: links are unwrapped to
// a bare email address so they classify as "email" rather than "url".
function linkToText(href) {
  if (!href) return "";
  if (/^mailto:/i.test(href)) return href.slice(7).split("?")[0];
  return href;
}

function classify(rawText) {
  const text = (rawText || "").trim();
  if (!text) return { type: null, text };
  if (CVE_RE.test(text)) return { type: "cve", text: text.toUpperCase() };
  if (URL_RE.test(text)) return { type: "url", text };
  if (isValidIPv4(text) || isValidIPv6(text)) return { type: "ip", text };
  if (HASH_RE.test(text)) return { type: "hash", text: text.toLowerCase() };
  if (EMAIL_RE.test(text)) return { type: "email", text: text.toLowerCase() };
  if (DOMAIN_RE.test(text) && !isValidIPv4(text)) return { type: "domain", text };
  if (isErrorCode(text)) return { type: "errorcode", text };
  return { type: "generic", text };
}

// Throws a friendly error if the current selection doesn't match what the
// clicked menu item expects (e.g. clicking "IP > Reputation" on a domain).
function requireType(expectedType, rawText, label) {
  const { type, text } = classify(rawText);
  if (type !== expectedType) {
    throw new Error(`"${(rawText || "").trim()}" doesn't look like a valid ${label}.`);
  }
  return text;
}

// Base (no-selection) labels for the always-visible top-level items whose
// type the current selection may or may not match. Their title only grows
// the selected text when it's actually usable for that lookup — e.g. an IP
// shouldn't show up next to "CVE lookup".
const BASE_TITLE = {
  [MENU_CVE]: "CVE lookup (NIST NVD)",
  [MENU_IP_PARENT]: "IP address",
  [MENU_DOMAIN_PARENT]: "Domain",
  [MENU_HASH_PARENT]: "File hash reputation",
  [MENU_URL_PARENT]: "URL",
  [MENU_EMAIL_PARENT]: "Email",
  [MENU_ERRORCODE_PARENT]: "Error code lookup",
};
const TITLE_TYPE = {
  [MENU_CVE]: "cve",
  [MENU_IP_PARENT]: "ip",
  [MENU_DOMAIN_PARENT]: "domain",
  [MENU_HASH_PARENT]: "hash",
  [MENU_URL_PARENT]: "url",
  [MENU_EMAIL_PARENT]: "email",
  [MENU_ERRORCODE_PARENT]: "errorcode",
};

function ignoreLastError() {
  void chrome.runtime.lastError;
}

// Reputation lookups work in a dual mode: with a stored key they call the
// service's API in-extension for a rich summary; without one they just open
// that service's own public lookup page in a new tab. Nothing needs to be
// hidden based on key presence — every item works either way.
async function getKey(storageKey) {
  const stored = await chrome.storage.local.get(storageKey);
  return stored[storageKey] || null;
}

function updateMenuState(rawText) {
  const { type, text } = classify(rawText);
  for (const menuId of Object.keys(BASE_TITLE)) {
    const base = BASE_TITLE[menuId];
    const title = type === TITLE_TYPE[menuId] ? `${base}: ${text}` : base;
    chrome.contextMenus.update(menuId, { title }, ignoreLastError);
  }
}

// Chrome 89+: fires just before the menu is displayed. Not every
// Chromium-based browser implements this (e.g. Vivaldi), so it's paired with
// a content-script fallback (see the onMessage listener below) that keeps
// menu state in sync as the user selects text on the page.
if (chrome.contextMenus.onShown) {
  chrome.contextMenus.onShown.addListener((info) => {
    updateMenuState(info.selectionText || linkToText(info.linkUrl));
    chrome.contextMenus.refresh();
  });
}

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "cyberToolkitSelection") {
    updateMenuState(message.text);
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: MENU_ROOT, title: "Cyber Toolkit", contexts: ["selection", "link"] });

  chrome.contextMenus.create({
    id: MENU_CVE,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_CVE],
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_IP_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_IP_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_INFO,
    parentId: MENU_IP_PARENT,
    title: "Info (RDAP + geolocation)",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_SHODAN,
    parentId: MENU_IP_PARENT,
    title: "Shodan (InternetDB)",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_PARENT,
    parentId: MENU_IP_PARENT,
    title: "Reputation",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_VT,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "VirusTotal",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_ABUSEIPDB,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "AbuseIPDB",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_GREYNOISE,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "GreyNoise Community",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_BARRACUDA,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "Barracuda Central",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_THREATFOX,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "ThreatFox",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_IP_REPUTATION_ALL,
    parentId: MENU_IP_REPUTATION_PARENT,
    title: "All",
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_DOMAIN_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_DOMAIN_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_INFO,
    parentId: MENU_DOMAIN_PARENT,
    title: "Info (RDAP)",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_CERTS,
    parentId: MENU_DOMAIN_PARENT,
    title: "Certificates (crt.sh)",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_SSL,
    parentId: MENU_DOMAIN_PARENT,
    title: "TLS/SSL grade (SSL Labs)",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_WAYBACK,
    parentId: MENU_DOMAIN_PARENT,
    title: "Wayback Machine",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_REPUTATION_PARENT,
    parentId: MENU_DOMAIN_PARENT,
    title: "Reputation",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_REPUTATION_VT,
    parentId: MENU_DOMAIN_REPUTATION_PARENT,
    title: "VirusTotal",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_REPUTATION_URLHAUS,
    parentId: MENU_DOMAIN_REPUTATION_PARENT,
    title: "URLhaus",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_REPUTATION_THREATFOX,
    parentId: MENU_DOMAIN_REPUTATION_PARENT,
    title: "ThreatFox",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_DOMAIN_REPUTATION_ALL,
    parentId: MENU_DOMAIN_REPUTATION_PARENT,
    title: "All",
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_HASH_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_HASH_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_HASH_VT,
    parentId: MENU_HASH_PARENT,
    title: "VirusTotal",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_HASH_THREATFOX,
    parentId: MENU_HASH_PARENT,
    title: "ThreatFox",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_HASH_MALWAREBAZAAR,
    parentId: MENU_HASH_PARENT,
    title: "MalwareBazaar",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_HASH_ALL,
    parentId: MENU_HASH_PARENT,
    title: "All",
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_URL_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_URL_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_URL_SCAN,
    parentId: MENU_URL_PARENT,
    title: "urlscan.io",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_URL_WAYBACK,
    parentId: MENU_URL_PARENT,
    title: "Wayback Machine",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_URL_ALL,
    parentId: MENU_URL_PARENT,
    title: "All",
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_EMAIL_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_EMAIL_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_EMAIL_MXTOOLBOX,
    parentId: MENU_EMAIL_PARENT,
    title: "MXToolbox",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_EMAIL_EMAILREP,
    parentId: MENU_EMAIL_PARENT,
    title: "EmailRep.io",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_EMAIL_ALL,
    parentId: MENU_EMAIL_PARENT,
    title: "All",
    contexts: ["selection", "link"],
  });

  chrome.contextMenus.create({
    id: MENU_ERRORCODE_PARENT,
    parentId: MENU_ROOT,
    title: BASE_TITLE[MENU_ERRORCODE_PARENT],
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_ERRORCODE_MS,
    parentId: MENU_ERRORCODE_PARENT,
    title: "Microsoft",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_ERRORCODE_HTTP,
    parentId: MENU_ERRORCODE_PARENT,
    title: "HTTP status code",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_ERRORCODE_ERRNO,
    parentId: MENU_ERRORCODE_PARENT,
    title: "Linux / POSIX errno",
    contexts: ["selection", "link"],
  });
  chrome.contextMenus.create({
    id: MENU_ERRORCODE_DB,
    parentId: MENU_ERRORCODE_PARENT,
    title: "Database error code",
    contexts: ["selection", "link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  const raw = info.selectionText || linkToText(info.linkUrl) || "";
  let type;
  let text;
  // Set when a lookup should also open an external site's own page — opened
  // only after the extension's own results tab, so that one appears first.
  let secondaryUrl = null;
  try {
    let data;
    switch (info.menuItemId) {
      case MENU_CVE:
        type = "cve";
        text = requireType("cve", raw, "CVE ID");
        secondaryUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(text)}`;
        data = await fetchCVE(text);
        break;
      case MENU_IP_INFO:
        type = "ip-info";
        text = requireType("ip", raw, "IP address");
        data = await fetchIPInfo(text);
        break;
      case MENU_IP_SHODAN:
        type = "ip-shodan";
        text = requireType("ip", raw, "IP address");
        data = await fetchShodanInternetDB(text);
        break;
      case MENU_IP_REPUTATION_VT:
        text = requireType("ip", raw, "IP address");
        await lookupIPReputationVT(text);
        return;
      case MENU_IP_REPUTATION_ABUSEIPDB:
        text = requireType("ip", raw, "IP address");
        await lookupIPReputationAbuseIPDB(text);
        return;
      case MENU_IP_REPUTATION_GREYNOISE:
        text = requireType("ip", raw, "IP address");
        await lookupIPReputationGreyNoise(text);
        return;
      case MENU_IP_REPUTATION_BARRACUDA:
        text = requireType("ip", raw, "IP address");
        await lookupIPReputationBarracuda(text);
        return;
      case MENU_IP_REPUTATION_THREATFOX:
        text = requireType("ip", raw, "IP address");
        await lookupIPReputationThreatFox(text);
        return;
      case MENU_IP_REPUTATION_ALL: {
        text = requireType("ip", raw, "IP address");
        await Promise.all([
          lookupIPReputationVT(text),
          lookupIPReputationAbuseIPDB(text),
          lookupIPReputationGreyNoise(text),
          lookupIPReputationBarracuda(text),
          lookupIPReputationThreatFox(text),
        ]);
        return;
      }
      case MENU_DOMAIN_INFO:
        type = "domain-info";
        text = requireType("domain", raw, "domain");
        data = await fetchDomainInfo(text);
        break;
      case MENU_DOMAIN_CERTS:
        type = "domain-certs";
        text = requireType("domain", raw, "domain");
        data = await fetchCertificates(text);
        break;
      case MENU_DOMAIN_SSL:
        type = "domain-ssl";
        text = requireType("domain", raw, "domain");
        data = await fetchSslLabs(text);
        break;
      case MENU_DOMAIN_WAYBACK:
        type = "domain-wayback";
        text = requireType("domain", raw, "domain");
        data = await fetchWayback(text);
        break;
      case MENU_DOMAIN_REPUTATION_VT:
        text = requireType("domain", raw, "domain");
        await lookupDomainReputationVT(text);
        return;
      case MENU_DOMAIN_REPUTATION_URLHAUS:
        text = requireType("domain", raw, "domain");
        await lookupDomainReputationURLhaus(text);
        return;
      case MENU_DOMAIN_REPUTATION_THREATFOX:
        text = requireType("domain", raw, "domain");
        await lookupDomainReputationThreatFox(text);
        return;
      case MENU_DOMAIN_REPUTATION_ALL: {
        text = requireType("domain", raw, "domain");
        await Promise.all([
          lookupDomainReputationVT(text),
          lookupDomainReputationURLhaus(text),
          lookupDomainReputationThreatFox(text),
        ]);
        return;
      }
      case MENU_HASH_VT:
        text = requireType("hash", raw, "MD5/SHA1/SHA256 hash");
        await lookupHashVT(text);
        return;
      case MENU_HASH_THREATFOX:
        text = requireType("hash", raw, "MD5/SHA1/SHA256 hash");
        await lookupHashThreatFox(text);
        return;
      case MENU_HASH_MALWAREBAZAAR:
        text = requireType("hash", raw, "MD5/SHA1/SHA256 hash");
        await lookupHashMalwareBazaar(text);
        return;
      case MENU_HASH_ALL: {
        text = requireType("hash", raw, "MD5/SHA1/SHA256 hash");
        await Promise.all([lookupHashVT(text), lookupHashThreatFox(text), lookupHashMalwareBazaar(text)]);
        return;
      }
      case MENU_URL_SCAN:
        text = requireType("url", raw, "URL");
        await lookupUrlScan(text);
        return;
      case MENU_URL_WAYBACK:
        text = requireType("url", raw, "URL");
        await lookupUrlWayback(text);
        return;
      case MENU_URL_ALL: {
        text = requireType("url", raw, "URL");
        await Promise.all([lookupUrlScan(text), lookupUrlWayback(text)]);
        return;
      }
      case MENU_EMAIL_MXTOOLBOX:
        text = requireType("email", raw, "email address");
        lookupEmailMXToolbox(text);
        return;
      case MENU_EMAIL_EMAILREP:
        text = requireType("email", raw, "email address");
        await lookupEmailRep(text);
        return;
      case MENU_EMAIL_ALL: {
        text = requireType("email", raw, "email address");
        lookupEmailMXToolbox(text);
        await lookupEmailRep(text);
        return;
      }
      case MENU_ERRORCODE_MS:
        chrome.tabs.create({
          url: `https://learn.microsoft.com/en-us/search/?terms=${encodeURIComponent(raw.trim())}`,
        });
        return;
      case MENU_ERRORCODE_HTTP:
        chrome.tabs.create({
          url: `https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/${encodeURIComponent(raw.trim())}`,
        });
        return;
      case MENU_ERRORCODE_ERRNO:
        // No official per-code page exists; open the full reference list.
        chrome.tabs.create({ url: "https://man7.org/linux/man-pages/man3/errno.3.html" });
        return;
      case MENU_ERRORCODE_DB: {
        const code = raw.trim();
        const oracleMatch = /^ORA-?(\d{5})$/i.exec(code);
        const url = oracleMatch
          ? `https://docs.oracle.com/error-help/db/ora-${oracleMatch[1]}/`
          : `https://www.google.com/search?q=${encodeURIComponent(`database error ${code}`)}`;
        chrome.tabs.create({ url });
        return;
      }
      default:
        return;
    }
    await openResults(type, text, data, null);
  } catch (err) {
    await openResults(type || "generic", raw.trim(), null, err.message || String(err));
  }
  if (secondaryUrl) chrome.tabs.create({ url: secondaryUrl });
});

async function fetchCVE(cveId) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`NVD API returned ${res.status}`);
  return res.json();
}

async function fetchIPInfo(ip) {
  const [rdap, geo] = await Promise.allSettled([
    fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`).then((r) =>
      r.ok ? r.json() : Promise.reject(new Error(`RDAP returned ${r.status}`))
    ),
    fetch(`https://ipwho.is/${encodeURIComponent(ip)}`).then((r) =>
      r.ok ? r.json() : Promise.reject(new Error(`ipwho.is returned ${r.status}`))
    ),
  ]);
  return {
    rdap: rdap.status === "fulfilled" ? rdap.value : { error: rdap.reason?.message },
    geo: geo.status === "fulfilled" ? geo.value : { error: geo.reason?.message },
  };
}

// Free, keyless, unlimited passive-recon feed: open ports, hostnames, CPEs,
// and known CVEs for an IP, without the paid full-Shodan API.
async function fetchShodanInternetDB(ip) {
  const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
  if (res.status === 404) return { notFound: true };
  if (!res.ok) throw new Error(`Shodan InternetDB returned ${res.status}`);
  return res.json();
}

// Each of these fully manages its own tab-opening/error handling so they can
// run independently — used both by their own menu item and, together, by
// "IP address > Reputation > All".
async function lookupIPReputationVT(ip) {
  try {
    const key = await getKey("virusTotalApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}/detection` });
      return;
    }
    const data = await fetchVT("ip_addresses", ip, key);
    await openResults("ip-reputation-vt", ip, data, null);
  } catch (err) {
    await openResults("ip-reputation-vt", ip, null, err.message || String(err));
  }
}

async function lookupIPReputationAbuseIPDB(ip) {
  try {
    const key = await getKey("abuseIpDbApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}` });
      return;
    }
    const data = await fetchAbuseIPDB(ip, key);
    await openResults("ip-reputation-abuseipdb", ip, data, null);
  } catch (err) {
    await openResults("ip-reputation-abuseipdb", ip, null, err.message || String(err));
  }
}

async function lookupIPReputationGreyNoise(ip) {
  try {
    const key = await getKey("greyNoiseApiKey");
    const data = await fetchGreyNoise(ip, key);
    await openResults("ip-reputation-greynoise", ip, data, null);
  } catch (err) {
    await openResults("ip-reputation-greynoise", ip, null, err.message || String(err));
  }
}

// Barracuda Central is a DNSBL: no key, no API of its own — always keyless.
async function lookupIPReputationBarracuda(ip) {
  try {
    const data = await fetchBarracuda(ip);
    await openResults("ip-reputation-barracuda", ip, data, null);
  } catch (err) {
    await openResults("ip-reputation-barracuda", ip, null, err.message || String(err));
  }
}

async function lookupIPReputationThreatFox(ip) {
  try {
    const key = await getKey("abuseChApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://threatfox.abuse.ch/browse.php?search=ioc%3a${encodeURIComponent(ip)}` });
      return;
    }
    const data = await fetchThreatFox(ip, key);
    await openResults("ip-reputation-threatfox", ip, data, null);
  } catch (err) {
    await openResults("ip-reputation-threatfox", ip, null, err.message || String(err));
  }
}

async function fetchDomainInfo(domain) {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
  return res.json();
}

async function lookupDomainReputationVT(domain) {
  try {
    const key = await getKey("virusTotalApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}/detection` });
      return;
    }
    const data = await fetchVT("domains", domain, key);
    await openResults("domain-reputation-vt", domain, data, null);
  } catch (err) {
    await openResults("domain-reputation-vt", domain, null, err.message || String(err));
  }
}

async function lookupDomainReputationURLhaus(domain) {
  try {
    const key = await getKey("abuseChApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://urlhaus.abuse.ch/host/${encodeURIComponent(domain)}/` });
      return;
    }
    const data = await fetchURLhaus(domain, key);
    await openResults("domain-reputation-urlhaus", domain, data, null);
  } catch (err) {
    await openResults("domain-reputation-urlhaus", domain, null, err.message || String(err));
  }
}

async function lookupDomainReputationThreatFox(domain) {
  try {
    const key = await getKey("abuseChApiKey");
    if (!key) {
      chrome.tabs.create({
        url: `https://threatfox.abuse.ch/browse.php?search=ioc%3a${encodeURIComponent(domain)}`,
      });
      return;
    }
    const data = await fetchThreatFox(domain, key);
    await openResults("domain-reputation-threatfox", domain, data, null);
  } catch (err) {
    await openResults("domain-reputation-threatfox", domain, null, err.message || String(err));
  }
}

async function fetchCertificates(domain) {
  const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`);
  if (!res.ok) {
    throw new Error(`crt.sh returned ${res.status} (it's occasionally overloaded — try again shortly)`);
  }
  return res.json();
}

// SSL Labs assessments are async and can take 1-2 minutes for a host that
// hasn't been scanned recently. This asks only for a cached result; if none
// exists yet, the renderer tells the user to check the public site instead
// of making them wait on a live scan.
async function fetchSslLabs(domain) {
  const res = await fetch(
    `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&fromCache=on&all=done`
  );
  if (!res.ok) throw new Error(`SSL Labs returned ${res.status}`);
  return res.json();
}

async function lookupHashVT(hash) {
  try {
    const key = await getKey("virusTotalApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}/detection` });
      return;
    }
    const data = await fetchVT("files", hash, key);
    await openResults("hash-vt", hash, data, null);
  } catch (err) {
    await openResults("hash-vt", hash, null, err.message || String(err));
  }
}

async function lookupHashThreatFox(hash) {
  try {
    const key = await getKey("abuseChApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://threatfox.abuse.ch/browse.php?search=ioc%3a${encodeURIComponent(hash)}` });
      return;
    }
    const data = await fetchThreatFox(hash, key);
    await openResults("hash-threatfox", hash, data, null);
  } catch (err) {
    await openResults("hash-threatfox", hash, null, err.message || String(err));
  }
}

async function lookupHashMalwareBazaar(hash) {
  try {
    const key = await getKey("abuseChApiKey");
    if (!key) {
      chrome.tabs.create({ url: `https://bazaar.abuse.ch/sample/${encodeURIComponent(hash)}/` });
      return;
    }
    const data = await fetchMalwareBazaar(hash, key);
    await openResults("hash-malwarebazaar", hash, data, null);
  } catch (err) {
    await openResults("hash-malwarebazaar", hash, null, err.message || String(err));
  }
}

// MXToolbox has no free JSON API worth calling — it's a domain/DNS tool, not
// a per-mailbox one, so this extracts the domain half of the address and
// opens MXToolbox's own blacklist check for it. Always keyless.
function lookupEmailMXToolbox(email) {
  const domain = email.split("@").pop();
  chrome.tabs.create({
    url: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${encodeURIComponent(domain)}&run=toolpage`,
  });
}

// Unlike the other reputation services, EmailRep.io has no public webpage to
// fall back to at all — it's API-only, so a key is required, not optional.
async function lookupEmailRep(email) {
  try {
    const key = await getKey("emailRepApiKey");
    if (!key) {
      throw new Error("This lookup needs a free EmailRep.io API key. Add one on the extension's Options page.");
    }
    const data = await fetchEmailRep(email, key);
    await openResults("email-emailrep", email, data, null);
  } catch (err) {
    await openResults("email-emailrep", email, null, err.message || String(err));
  }
}

// {notFound: true} on a 404, or the raw VT v3 JSON response otherwise.
// Only called once a key is confirmed present (see the click handler).
async function fetchVT(kind, value, key) {
  const res = await fetch(`https://www.virustotal.com/api/v3/${kind}/${encodeURIComponent(value)}`, {
    headers: { "x-apikey": key },
  });
  if (res.status === 404) return { notFound: true };
  if (res.status === 401) {
    throw new Error("VirusTotal rejected the stored API key (401). Check it on the Options page.");
  }
  if (!res.ok) throw new Error(`VirusTotal returned ${res.status}`);
  return res.json();
}

async function fetchAbuseIPDB(ip, key) {
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { headers: { Key: key, Accept: "application/json" } }
  );
  if (res.status === 401 || res.status === 403) {
    throw new Error("AbuseIPDB rejected the stored API key. Check it on the Options page.");
  }
  if (!res.ok) throw new Error(`AbuseIPDB returned ${res.status}`);
  return res.json();
}

async function fetchEmailRep(email, key) {
  const res = await fetch(`https://emailrep.io/${encodeURIComponent(email)}`, {
    headers: { Key: key },
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error("EmailRep.io rejected the stored API key. Check it on the Options page.");
  }
  if (res.status === 429) throw new Error("EmailRep.io rate limit reached. Try again shortly.");
  if (!res.ok) throw new Error(`EmailRep.io returned ${res.status}`);
  return res.json();
}

// GreyNoise's community endpoint works without a key at all (an optional key
// just raises the rate limit); a 404 is a normal "not observed scanning" reply
// with a real body, not a failure — only 400/5xx are treated as errors.
async function fetchGreyNoise(ip, key) {
  const headers = { Accept: "application/json" };
  if (key) headers.key = key;
  const res = await fetch(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { headers });
  if (res.status === 400) throw new Error("That doesn't look like a routable IPv4 address to GreyNoise.");
  if (res.status >= 500) throw new Error(`GreyNoise returned ${res.status}`);
  return res.json();
}

// abuse.ch's unified API requires a free Auth-Key on every request.
async function fetchURLhaus(host, key) {
  const res = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded" },
    body: `host=${encodeURIComponent(host)}`,
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error("URLhaus rejected the stored API key. Check it on the Options page.");
  }
  if (!res.ok) throw new Error(`URLhaus returned ${res.status}`);
  return res.json();
}

// ThreatFox accepts any indicator type (IP, domain, or hash) via the same
// search_ioc query — shared Auth-Key with URLhaus/MalwareBazaar (one abuse.ch
// account covers all three).
async function fetchThreatFox(indicator, key) {
  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/json" },
    body: JSON.stringify({ query: "search_ioc", search_term: indicator }),
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error("ThreatFox rejected the stored API key. Check it on the Options page.");
  }
  if (!res.ok) throw new Error(`ThreatFox returned ${res.status}`);
  return res.json();
}

async function fetchMalwareBazaar(hash, key) {
  const res = await fetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded" },
    body: `query=get_info&hash=${encodeURIComponent(hash)}`,
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error("MalwareBazaar rejected the stored API key. Check it on the Options page.");
  }
  if (!res.ok) throw new Error(`MalwareBazaar returned ${res.status}`);
  return res.json();
}

// urlscan.io's search endpoint (existing scans) is fully public — no key
// needed. Submitting a *new* scan needs a key and takes 10-40s to complete,
// which doesn't fit a single request/response cycle well, so this only
// searches for prior scans rather than triggering a fresh one.
async function fetchUrlscan(url) {
  const res = await fetch(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`page.url:"${url}"`)}&size=5`);
  if (!res.ok) throw new Error(`urlscan.io returned ${res.status}`);
  return res.json();
}

// Free, keyless. Works for both a bare domain and a full URL.
async function fetchWayback(urlOrDomain) {
  const res = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(urlOrDomain)}`);
  if (!res.ok) throw new Error(`Wayback Machine returned ${res.status}`);
  return res.json();
}

// Self-contained (own error handling + results tab) so they can run together
// via "URL > All" the same way the reputation lookups do.
async function lookupUrlScan(url) {
  try {
    const data = await fetchUrlscan(url);
    await openResults("url-scan", url, data, null);
  } catch (err) {
    await openResults("url-scan", url, null, err.message || String(err));
  }
}

async function lookupUrlWayback(url) {
  try {
    const data = await fetchWayback(url);
    await openResults("url-wayback", url, data, null);
  } catch (err) {
    await openResults("url-wayback", url, null, err.message || String(err));
  }
}

// Barracuda Reputation is a DNS blocklist: listed IPs answer with an A
// record (typically 127.0.0.2) for the reversed-octet query below. Queried
// via Cloudflare's DNS-over-HTTPS resolver since a service worker can't do
// raw DNS lookups directly. IPv4-only, like all classic DNSBLs.
async function fetchBarracuda(ip) {
  const octets = ip.split(".");
  if (octets.length !== 4) {
    throw new Error("Barracuda Reputation only supports IPv4 addresses.");
  }
  const query = `${octets.reverse().join(".")}.b.barracudacentral.org`;
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`, {
    headers: { Accept: "application/dns-json" },
  });
  if (!res.ok) throw new Error(`Barracuda DNSBL lookup returned ${res.status}`);
  const json = await res.json();
  const answers = Array.isArray(json.Answer) ? json.Answer : [];
  return { ip, query, listed: answers.some((a) => a.type === 1), answers };
}

async function openResults(type, query, data, error) {
  const id = crypto.randomUUID();
  await chrome.storage.session.set({
    [id]: { type, query, data, error, fetchedAt: Date.now() },
  });
  chrome.tabs.create({ url: `results.html?id=${id}` });
}

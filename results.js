const params = new URLSearchParams(location.search);
const id = params.get("id");

const titleEl = document.getElementById("title");
const subtitleEl = document.getElementById("subtitle");
const contentEl = document.getElementById("content");

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else node.setAttribute(k, v);
  }
  for (const child of [].concat(children)) {
    if (child) node.appendChild(child);
  }
  return node;
}

function fieldRow(label, value) {
  return el("div", { class: "field-row" }, [
    el("div", { class: "label", text: label }),
    el("div", { class: "value" }, typeof value === "string" ? el("span", { text: value }) : value),
  ]);
}

function rawDetails(data) {
  return el("details", { class: "raw" }, [
    el("summary", { text: "Raw response" }),
    el("pre", { text: JSON.stringify(data, null, 2) }),
  ]);
}

function severityBadge(score, label) {
  let cls = "warn";
  if (score >= 7) cls = "bad";
  else if (score < 4) cls = "good";
  return el("span", { class: `badge ${cls}`, text: `${label} (${score})` });
}

function vtStatsBadge(stats) {
  if (!stats) return null;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  let cls = "good";
  let label = "Clean";
  if (malicious > 0) {
    cls = "bad";
    label = `${malicious} malicious`;
  } else if (suspicious > 0) {
    cls = "warn";
    label = `${suspicious} suspicious`;
  }
  return el("span", { class: `badge ${cls}`, text: `${label} / ${total} engines` });
}

// Renders a standalone VirusTotal reputation result (used for IP/domain
// reputation and file-hash lookups, all of which return the same VT v3 shape).
// data is: {notFound: true} on a 404, or the raw VT v3 JSON response.
function renderReputation(query, data, extraFields = () => []) {
  if (data?.notFound) {
    contentEl.appendChild(el("p", { class: "error", text: `No VirusTotal record found for ${query}.` }));
    contentEl.appendChild(rawDetails(data));
    return;
  }
  const attrs = data?.data?.attributes;
  if (!attrs) {
    contentEl.appendChild(el("p", { class: "error", text: "No data returned." }));
    contentEl.appendChild(rawDetails(data));
    return;
  }
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  const badge = vtStatsBadge(attrs.last_analysis_stats);
  if (badge) card.appendChild(fieldRow("Detections", badge));
  if (typeof attrs.reputation === "number") {
    card.appendChild(fieldRow("Community reputation", String(attrs.reputation)));
  }
  if (attrs.popular_threat_classification?.suggested_threat_label) {
    card.appendChild(fieldRow("Threat label", attrs.popular_threat_classification.suggested_threat_label));
  }
  extraFields(attrs).forEach((row) => card.appendChild(row));
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderCVE(query, data) {
  const vuln = data?.vulnerabilities?.[0]?.cve;
  if (!vuln) {
    contentEl.appendChild(el("p", { class: "error", text: `No CVE record found for ${query}.` }));
    contentEl.appendChild(rawDetails(data));
    return;
  }
  const desc =
    vuln.descriptions?.find((d) => d.lang === "en")?.value || "No description available.";
  const metrics =
    vuln.metrics?.cvssMetricV31?.[0] ||
    vuln.metrics?.cvssMetricV30?.[0] ||
    vuln.metrics?.cvssMetricV2?.[0];
  const cvssData = metrics?.cvssData;

  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: vuln.id }));
  card.appendChild(fieldRow("Status", vuln.vulnStatus || "Unknown"));
  card.appendChild(fieldRow("Published", vuln.published || "—"));
  card.appendChild(fieldRow("Last modified", vuln.lastModified || "—"));
  if (cvssData) {
    card.appendChild(
      fieldRow("CVSS", severityBadge(cvssData.baseScore, cvssData.baseSeverity || metrics.baseSeverity || ""))
    );
    if (cvssData.vectorString) card.appendChild(fieldRow("Vector", cvssData.vectorString));
  }
  card.appendChild(fieldRow("Description", desc));
  contentEl.appendChild(card);

  const refs = vuln.references || [];
  if (refs.length) {
    const refsCard = el("div", { class: "card" });
    refsCard.appendChild(el("h2", { text: "References" }));
    const list = el("ul", { class: "refs" });
    refs.slice(0, 15).forEach((r) => {
      const li = el("li");
      li.appendChild(el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: r.url }));
      list.appendChild(li);
    });
    refsCard.appendChild(list);
    contentEl.appendChild(refsCard);
  }
  contentEl.appendChild(rawDetails(data));
}

function rdapEntityName(rdap) {
  const entity = rdap?.entities?.[0];
  const vcard = entity?.vcardArray?.[1];
  const fn = vcard?.find((v) => v[0] === "fn");
  return fn?.[3] || entity?.handle || "—";
}

function renderIPInfo(query, data) {
  const { rdap, geo } = data || {};
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (geo && !geo.error) {
    card.appendChild(
      fieldRow("Location", [geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "—")
    );
    card.appendChild(fieldRow("ASN / ISP", `${geo.connection?.asn ? "AS" + geo.connection.asn + " " : ""}${geo.connection?.org || geo.connection?.isp || "—"}`));
    card.appendChild(fieldRow("Timezone", geo.timezone?.id || "—"));
  } else if (geo?.error) {
    card.appendChild(fieldRow("Geolocation", `Lookup failed: ${geo.error}`));
  }
  if (rdap && !rdap.error) {
    card.appendChild(fieldRow("Network name", rdap.name || "—"));
    card.appendChild(fieldRow("Registered to", rdapEntityName(rdap)));
    card.appendChild(fieldRow("Range", `${rdap.startAddress || "?"} – ${rdap.endAddress || "?"}`));
    card.appendChild(fieldRow("Country", rdap.country || "—"));
  } else if (rdap?.error) {
    card.appendChild(fieldRow("RDAP", `Lookup failed: ${rdap.error}`));
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderShodan(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (data?.notFound) {
    card.appendChild(fieldRow("Result", "No InternetDB data for this IP (nothing observed exposed)."));
  } else {
    const ports = data?.ports || [];
    const vulns = data?.vulns || [];
    card.appendChild(
      fieldRow(
        "Open ports",
        ports.length ? el("span", { class: "badge warn", text: ports.join(", ") }) : "None observed"
      )
    );
    if (vulns.length) {
      card.appendChild(fieldRow("Known CVEs", el("span", { class: "badge bad", text: vulns.join(", ") })));
    }
    if (data?.hostnames?.length) card.appendChild(fieldRow("Hostnames", data.hostnames.join(", ")));
    if (data?.cpes?.length) card.appendChild(fieldRow("CPEs", data.cpes.join(", ")));
    if (data?.tags?.length) card.appendChild(fieldRow("Tags", data.tags.join(", ")));
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

// Shared by Domain > Wayback Machine and URL > Wayback Machine — same
// archive.org availability-check response shape either way.
function renderWayback(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  const snapshot = data?.archived_snapshots?.closest;
  if (!snapshot?.available) {
    card.appendChild(fieldRow("Result", "No archived snapshot found."));
  } else {
    card.appendChild(fieldRow("Snapshot available", el("span", { class: "badge good", text: snapshot.status || "200" })));
    card.appendChild(fieldRow("Captured", snapshot.timestamp || "—"));
    card.appendChild(
      fieldRow(
        "View snapshot",
        el("a", { href: snapshot.url, target: "_blank", rel: "noopener noreferrer", text: snapshot.url })
      )
    );
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderDomainInfo(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  card.appendChild(fieldRow("Status", (data.status || []).join(", ") || "—"));

  const events = data.events || [];
  const findEvent = (action) => events.find((e) => e.eventAction === action)?.eventDate;
  card.appendChild(fieldRow("Registered", findEvent("registration") || "—"));
  card.appendChild(fieldRow("Expires", findEvent("expiration") || "—"));
  card.appendChild(fieldRow("Last changed", findEvent("last changed") || "—"));

  const registrarEntity = data.entities?.find((e) => e.roles?.includes("registrar"));
  card.appendChild(fieldRow("Registrar", rdapEntityName(registrarEntity ? { entities: [registrarEntity] } : null)));

  const nameservers = (data.nameservers || []).map((ns) => ns.ldhName).filter(Boolean);
  if (nameservers.length) {
    card.appendChild(fieldRow("Name servers", nameservers.join(", ")));
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderAbuseIPDB(query, data) {
  const d = data?.data;
  if (!d) {
    contentEl.appendChild(el("p", { class: "error", text: "No data returned." }));
    contentEl.appendChild(rawDetails(data));
    return;
  }
  const score = d.abuseConfidenceScore ?? 0;
  let cls = "good";
  if (score >= 50) cls = "bad";
  else if (score > 0) cls = "warn";

  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  card.appendChild(fieldRow("Abuse confidence", el("span", { class: `badge ${cls}`, text: `${score}%` })));
  card.appendChild(fieldRow("Total reports", String(d.totalReports ?? 0)));
  card.appendChild(fieldRow("Distinct reporters", String(d.numDistinctUsers ?? 0)));
  card.appendChild(fieldRow("Last reported", d.lastReportedAt || "Never"));
  card.appendChild(fieldRow("ISP", d.isp || "—"));
  card.appendChild(fieldRow("Usage type", d.usageType || "—"));
  card.appendChild(fieldRow("Country", d.countryCode || "—"));
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderGreyNoise(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (data?.noise || data?.riot) {
    let cls = "warn";
    if (data.classification === "malicious") cls = "bad";
    else if (data.classification === "benign") cls = "good";
    card.appendChild(
      fieldRow("Classification", el("span", { class: `badge ${cls}`, text: data.classification || "unknown" }))
    );
    if (data.name) card.appendChild(fieldRow("Actor / scanner name", data.name));
    if (data.last_seen) card.appendChild(fieldRow("Last seen", data.last_seen));
    if (data.riot) card.appendChild(fieldRow("RIOT", "Known benign business service"));
  } else {
    card.appendChild(fieldRow("Result", data?.message || "Not observed scanning the internet."));
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderURLhaus(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));

  if (data?.query_status === "no_results") {
    card.appendChild(fieldRow("Result", "No malicious URLs found on this host."));
  } else if (data?.query_status !== "ok") {
    card.appendChild(
      el("p", { class: "error", text: `URLhaus: ${data?.query_status || "unknown response"}` })
    );
  } else {
    card.appendChild(fieldRow("URLs seen", String(data.url_count ?? "0")));
    card.appendChild(fieldRow("First seen", data.firstseen || "—"));
    if (data.blacklists) {
      const entries = Object.entries(data.blacklists)
        .map(([list, status]) => `${list}: ${status}`)
        .join(", ");
      if (entries) card.appendChild(fieldRow("Blacklists", entries));
    }
    if (data.urlhaus_reference) {
      card.appendChild(
        fieldRow(
          "Reference",
          el("a", {
            href: data.urlhaus_reference,
            target: "_blank",
            rel: "noopener noreferrer",
            text: "View on URLhaus",
          })
        )
      );
    }
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderBarracuda(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  const cls = data?.listed ? "bad" : "good";
  const label = data?.listed ? "Listed (reputation issue)" : "Not listed";
  card.appendChild(fieldRow("Barracuda Reputation", el("span", { class: `badge ${cls}`, text: label })));
  card.appendChild(fieldRow("DNSBL query", data?.query || "—"));
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderEmailRep(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));

  const repCls = { high: "good", medium: "warn", low: "bad", none: "warn" }[data?.reputation] || "warn";
  card.appendChild(fieldRow("Reputation", el("span", { class: `badge ${repCls}`, text: data?.reputation || "unknown" })));
  card.appendChild(fieldRow("Suspicious", data?.suspicious ? "Yes" : "No"));

  const d = data?.details || {};
  const flags = [
    d.malicious_activity && "malicious activity",
    d.credentials_leaked && "credentials leaked",
    d.data_breach && "data breach",
    d.spam && "spam",
    d.disposable && "disposable address",
    d.spoofable && "spoofable sender",
  ].filter(Boolean);
  if (flags.length) card.appendChild(fieldRow("Flags", flags.join(", ")));

  if (typeof d.days_since_domain_creation === "number") {
    card.appendChild(fieldRow("Domain age", `${d.days_since_domain_creation} days`));
  }
  if (typeof d.deliverable === "boolean") {
    card.appendChild(fieldRow("Deliverable", d.deliverable ? "Yes" : "No"));
  }
  if (typeof d.free_provider === "boolean") {
    card.appendChild(fieldRow("Free provider", d.free_provider ? "Yes" : "No"));
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderHash(query, data) {
  renderReputation(query, data, (attrs) => {
    const rows = [];
    if (attrs.meaningful_name) rows.push(fieldRow("File name", attrs.meaningful_name));
    if (attrs.type_description) rows.push(fieldRow("File type", attrs.type_description));
    if (attrs.size) rows.push(fieldRow("Size", `${attrs.size.toLocaleString()} bytes`));
    rows.push(fieldRow("MD5", attrs.md5 || "—"));
    rows.push(fieldRow("SHA1", attrs.sha1 || "—"));
    rows.push(fieldRow("SHA256", attrs.sha256 || "—"));
    return rows;
  });
}

// Used for IP/domain/hash ThreatFox lookups — same search_ioc response shape
// regardless of which indicator type was searched.
function renderThreatFox(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (data?.query_status === "no_result") {
    card.appendChild(fieldRow("Result", "No ThreatFox IOC records found."));
  } else if (data?.query_status !== "ok") {
    card.appendChild(el("p", { class: "error", text: `ThreatFox: ${data?.query_status || "unknown response"}` }));
  } else {
    const records = data.data || [];
    card.appendChild(fieldRow("Matching IOCs", el("span", { class: "badge bad", text: String(records.length) })));
    records.slice(0, 5).forEach((r) => {
      card.appendChild(
        fieldRow(
          r.malware_printable || r.threat_type_desc || "IOC",
          `${r.confidence_level ?? "?"}% confidence — first seen ${r.first_seen || "—"}`
        )
      );
    });
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderMalwareBazaar(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (data?.query_status === "hash_not_found") {
    card.appendChild(fieldRow("Result", "No MalwareBazaar record found for this hash."));
  } else if (data?.query_status !== "ok") {
    card.appendChild(el("p", { class: "error", text: `MalwareBazaar: ${data?.query_status || "unknown response"}` }));
  } else {
    const sample = data.data?.[0];
    if (sample) {
      card.appendChild(fieldRow("Malware family", el("span", { class: "badge bad", text: sample.signature || "Unknown" })));
      card.appendChild(fieldRow("File name", sample.file_name || "—"));
      card.appendChild(fieldRow("File type", sample.file_type || "—"));
      if (sample.file_size) card.appendChild(fieldRow("Size", `${Number(sample.file_size).toLocaleString()} bytes`));
      card.appendChild(fieldRow("First seen", sample.first_seen || "—"));
      if (sample.tags?.length) card.appendChild(fieldRow("Tags", sample.tags.join(", ")));
    }
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

// crt.sh returns a bare array of cert log entries (not wrapped in an object).
function renderCertificates(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  const certs = Array.isArray(data) ? data : [];
  if (!certs.length) {
    card.appendChild(fieldRow("Result", "No certificates found on crt.sh."));
  } else {
    card.appendChild(fieldRow("Certificates found", String(certs.length)));
    const names = new Set();
    certs.forEach((c) => (c.name_value || "").split("\n").forEach((n) => n.trim() && names.add(n.trim())));
    const uniqueNames = [...names].sort();
    card.appendChild(fieldRow("Unique names seen", String(uniqueNames.length)));

    const latest = [...certs].sort((a, b) => new Date(b.entry_timestamp) - new Date(a.entry_timestamp))[0];
    if (latest) {
      card.appendChild(fieldRow("Most recent issuer", latest.issuer_name || "—"));
      card.appendChild(fieldRow("Most recent cert validity", `${latest.not_before || "?"} – ${latest.not_after || "?"}`));
    }
    if (uniqueNames.length) {
      const shown = uniqueNames.slice(0, 15).join(", ") + (uniqueNames.length > 15 ? ", …" : "");
      card.appendChild(fieldRow("Names", shown));
    }
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderSslLabs(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  if (data?.status === "READY") {
    const endpoints = data.endpoints || [];
    if (!endpoints.length) {
      card.appendChild(fieldRow("Result", "Scan ready, but no endpoint grades were returned."));
    }
    endpoints.forEach((ep, i) => {
      const grade = ep.grade || "?";
      const cls = grade.startsWith("A") ? "good" : grade.startsWith("B") || grade.startsWith("C") ? "warn" : "bad";
      card.appendChild(
        fieldRow(ep.ipAddress || `Endpoint ${i + 1}`, el("span", { class: `badge ${cls}`, text: grade }))
      );
    });
  } else if (data?.status === "ERROR") {
    card.appendChild(el("p", { class: "error", text: `SSL Labs error: ${data.statusMessage || "unknown error"}` }));
  } else {
    card.appendChild(fieldRow("Status", data?.status || "unknown"));
    card.appendChild(
      el("p", {
        class: "muted",
        text: "No cached result yet — SSL Labs assessments can take 1-2 minutes for a host that hasn't been tested recently.",
      })
    );
    card.appendChild(
      fieldRow(
        "Live scan",
        el("a", {
          href: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(query)}`,
          target: "_blank",
          rel: "noopener noreferrer",
          text: "View live progress on SSL Labs",
        })
      )
    );
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

function renderUrlscan(query, data) {
  const card = el("div", { class: "card" });
  card.appendChild(el("h2", { text: query }));
  const results = data?.results || [];
  if (!results.length) {
    card.appendChild(fieldRow("Result", "No prior urlscan.io scan found for this URL."));
    card.appendChild(
      fieldRow(
        "Submit a scan",
        el("a", {
          href: `https://urlscan.io/search/#${encodeURIComponent(query)}`,
          target: "_blank",
          rel: "noopener noreferrer",
          text: "Search / submit on urlscan.io",
        })
      )
    );
  } else {
    const latest = results[0];
    card.appendChild(fieldRow("Prior scans found", String(data.total ?? results.length)));
    card.appendChild(fieldRow("Page title", latest.page?.title || "—"));
    card.appendChild(fieldRow("Final URL", latest.page?.url || latest.task?.url || "—"));
    card.appendChild(fieldRow("Server / IP", `${latest.page?.server || "—"} (${latest.page?.ip || "—"})`));
    card.appendChild(fieldRow("Scanned", latest.task?.time || "—"));
    if (latest.result) {
      card.appendChild(
        fieldRow(
          "Full report",
          el("a", { href: latest.result, target: "_blank", rel: "noopener noreferrer", text: "View on urlscan.io" })
        )
      );
    }
    if (latest.screenshot) {
      card.appendChild(
        el("img", { src: latest.screenshot, alt: "Screenshot", style: "max-width:100%;border-radius:8px;margin-top:8px;" })
      );
    }
  }
  contentEl.appendChild(card);
  contentEl.appendChild(rawDetails(data));
}

async function main() {
  if (!id) {
    contentEl.textContent = "";
    contentEl.appendChild(el("p", { class: "error", text: "No result id provided." }));
    return;
  }
  const store = await chrome.storage.session.get(id);
  const record = store[id];
  contentEl.textContent = "";

  if (!record) {
    contentEl.appendChild(el("p", { class: "error", text: "Result not found (it may have expired)." }));
    return;
  }

  const { type, query, data, error } = record;
  titleEl.textContent = `Cyber Toolkit — ${query}`;
  subtitleEl.textContent =
    {
      cve: "CVE lookup (NVD)",
      "ip-info": "IP network & geolocation info",
      "ip-reputation-vt": "IP reputation (VirusTotal)",
      "ip-reputation-abuseipdb": "IP reputation (AbuseIPDB)",
      "ip-reputation-greynoise": "IP reputation (GreyNoise Community)",
      "ip-reputation-barracuda": "IP reputation (Barracuda Central)",
      "ip-reputation-threatfox": "IP reputation (ThreatFox)",
      "ip-shodan": "IP exposure (Shodan InternetDB)",
      "domain-info": "Domain registration info (RDAP)",
      "domain-certs": "Domain certificates (crt.sh)",
      "domain-ssl": "Domain TLS/SSL grade (SSL Labs)",
      "domain-wayback": "Domain history (Wayback Machine)",
      "domain-reputation-vt": "Domain reputation (VirusTotal)",
      "domain-reputation-urlhaus": "Domain reputation (URLhaus)",
      "domain-reputation-threatfox": "Domain reputation (ThreatFox)",
      "hash-vt": "File hash reputation (VirusTotal)",
      "hash-threatfox": "File hash reputation (ThreatFox)",
      "hash-malwarebazaar": "File hash reputation (MalwareBazaar)",
      "url-scan": "URL lookup (urlscan.io)",
      "url-wayback": "URL history (Wayback Machine)",
      "email-emailrep": "Email reputation (EmailRep.io)",
    }[type] || "Lookup";

  if (error) {
    contentEl.appendChild(el("p", { class: "error", text: `Lookup failed: ${error}` }));
    if (
      error.includes("VirusTotal") ||
      error.includes("AbuseIPDB") ||
      error.includes("URLhaus") ||
      error.includes("ThreatFox") ||
      error.includes("MalwareBazaar") ||
      error.includes("EmailRep")
    ) {
      const link = el("a", { href: "#", text: "Open Options to add an API key" });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
      });
      contentEl.appendChild(el("p", {}, link));
    }
    return;
  }

  if (type === "cve") renderCVE(query, data);
  else if (type === "ip-info") renderIPInfo(query, data);
  else if (type === "ip-reputation-vt") renderReputation(query, data);
  else if (type === "ip-reputation-abuseipdb") renderAbuseIPDB(query, data);
  else if (type === "ip-reputation-greynoise") renderGreyNoise(query, data);
  else if (type === "ip-reputation-barracuda") renderBarracuda(query, data);
  else if (type === "ip-reputation-threatfox") renderThreatFox(query, data);
  else if (type === "ip-shodan") renderShodan(query, data);
  else if (type === "domain-info") renderDomainInfo(query, data);
  else if (type === "domain-certs") renderCertificates(query, data);
  else if (type === "domain-ssl") renderSslLabs(query, data);
  else if (type === "domain-wayback") renderWayback(query, data);
  else if (type === "domain-reputation-vt") renderReputation(query, data);
  else if (type === "domain-reputation-urlhaus") renderURLhaus(query, data);
  else if (type === "domain-reputation-threatfox") renderThreatFox(query, data);
  else if (type === "hash-vt") renderHash(query, data);
  else if (type === "hash-threatfox") renderThreatFox(query, data);
  else if (type === "hash-malwarebazaar") renderMalwareBazaar(query, data);
  else if (type === "url-scan") renderUrlscan(query, data);
  else if (type === "url-wayback") renderWayback(query, data);
  else if (type === "email-emailrep") renderEmailRep(query, data);
  else contentEl.appendChild(rawDetails(data));
}

main();

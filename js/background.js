const KEYWORDS_KEY = "kf_keywords";
const FINDINGS_KEY = "kf_findings";

const DEFAULT_KEYWORDS = [
  "key", "api_key", "apikey", "api-key", "secret", "token",
  "access_token", "auth", "credential", "password",
  "client_id", "client_secret"
];

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await chrome.storage.local.set({
      [KEYWORDS_KEY]: DEFAULT_KEYWORDS,
      [FINDINGS_KEY]: []
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "finding") {
    saveFinding(request.data).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "getKeywords") {
    getKeywords().then((keywords) => sendResponse({ keywords }));
    return true;
  }
  if (request.type === "getFindings") {
    getFindings().then((findings) => sendResponse({ findings }));
    return true;
  }
  if (request.type === "addKeyword") {
    addKeyword(request.keyword).then((result) => sendResponse(result));
    return true;
  }
  if (request.type === "removeKeyword") {
    removeKeyword(request.keyword).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "removeFinding") {
    removeFinding(request.url).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "clearFindings") {
    clearFindings().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (request.type === "exportFindings") {
    getFindings().then((findings) => sendResponse({ findings }));
    return true;
  }
});

async function getKeywords() {
  const result = await chrome.storage.local.get(KEYWORDS_KEY);
  return result[KEYWORDS_KEY] || DEFAULT_KEYWORDS;
}

async function addKeyword(keyword) {
  const keywords = await getKeywords();
  const normalized = keyword.trim().toLowerCase();
  if (!normalized) return { ok: false, error: "Keyword cannot be empty." };
  if (keywords.includes(normalized)) return { ok: false, error: "Keyword already exists." };
  keywords.push(normalized);
  await chrome.storage.local.set({ [KEYWORDS_KEY]: keywords });
  return { ok: true };
}

async function removeKeyword(keyword) {
  const keywords = await getKeywords();
  await chrome.storage.local.set({ [KEYWORDS_KEY]: keywords.filter((k) => k !== keyword) });
}

async function getFindings() {
  const result = await chrome.storage.local.get(FINDINGS_KEY);
  return result[FINDINGS_KEY] || [];
}

async function saveFinding(finding) {
  const findings = await getFindings();
  const isDuplicate = findings.some(
    (f) => f.url === finding.url && f.match === finding.match
  );
  if (isDuplicate) return;
  findings.push(finding);
  await chrome.storage.local.set({ [FINDINGS_KEY]: findings });

  const badgeCount = findings.length;
  chrome.action.setBadgeText({ text: badgeCount > 0 ? String(badgeCount) : "" });
  chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
}

async function removeFinding(url) {
  const findings = await getFindings();
  const updated = findings.filter((f) => f.url !== url);
  await chrome.storage.local.set({ [FINDINGS_KEY]: updated });
  chrome.action.setBadgeText({ text: updated.length > 0 ? String(updated.length) : "" });
}

async function clearFindings() {
  await chrome.storage.local.set({ [FINDINGS_KEY]: [] });
  chrome.action.setBadgeText({ text: "" });
}

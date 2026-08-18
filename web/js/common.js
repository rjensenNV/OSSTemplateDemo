// Shared helpers for the CUDA-X Developer Intelligence dashboard.

async function loadJSON(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error("failed to load " + path + ": " + r.status);
  return r.json();
}

function fmtDate(s) { return s ? String(s).slice(0, 10) : "—"; }

// Monthly aggregates describe completed calendar months, except for the last
// point when it is the still-open month containing the collection timestamp.
// Give charts real UTC dates so a snapshot taken on August 3 does not visually
// occupy all of August.
function monthlyTimeline(months, asOf) {
  if (!Array.isArray(months) || !months.length) return [];
  const asOfMatch = String(asOf || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
  const asOfTimestamp = asOfMatch
    ? Date.UTC(+asOfMatch[1], +asOfMatch[2] - 1, +asOfMatch[3])
    : null;
  return months.map(function (month, index) {
    const match = String(month || "").match(/^(\d{4})-(\d{2})$/);
    if (!match) return null;
    const year = +match[1], monthNumber = +match[2];
    if (monthNumber < 1 || monthNumber > 12) return null;
    const monthStart = Date.UTC(year, monthNumber - 1, 1);
    const monthEnd = Date.UTC(year, monthNumber, 0);
    let timestamp = monthEnd, partial = false;
    if (
      index === months.length - 1 && asOfMatch &&
      +asOfMatch[1] === year && +asOfMatch[2] === monthNumber &&
      asOfTimestamp >= monthStart && asOfTimestamp <= monthEnd
    ) {
      timestamp = asOfTimestamp;
      partial = timestamp < monthEnd;
    }
    const date = new Date(timestamp);
    return {
      month: month,
      timestamp: timestamp,
      date: date.getUTCFullYear() + "-" +
        String(date.getUTCMonth() + 1).padStart(2, "0") + "-" +
        String(date.getUTCDate()).padStart(2, "0"),
      partial: partial
    };
  }).filter(Boolean);
}

function timelineAxisLabel(value) {
  const date = new Date(+value);
  if (!Number.isFinite(date.getTime())) return "";
  return date.getUTCFullYear() + "-" + String(date.getUTCMonth() + 1).padStart(2, "0");
}

function timelineTooltipLabel(value, timeline) {
  const timestamp = +value;
  const point = (timeline || []).find(function (candidate) {
    return candidate.timestamp === timestamp;
  });
  if (!point) return timelineAxisLabel(timestamp);
  return point.partial ? point.date + " (partial month)" : point.month;
}

// Distinct color per AI agent for badges.
const AGENT_COLOR = {
  "Claude Code": "#d97757",
  "GitHub Copilot": "#8b949e",
  "OpenAI Codex": "#10a37f",
  "Aider": "#b180ff",
  "Devin": "#5b8def",
  "Google Jules": "#fbbc05",
  "Gemini Code Assist": "#fbbc05",
  "OpenHands": "#ff7b72",
  "Codegen": "#79c0ff",
  "Tembo": "#f778ba"
};

function agentBadges(agents, onIntegration) {
  // agents: {label: commit_count}. onIntegration: labels flagged on the integration commit.
  const keys = Object.keys(agents || {});
  if (!keys.length) return '<span class="muted">none detected</span>';
  const oi = new Set(onIntegration || []);
  return keys.map(function (k) {
    const c = AGENT_COLOR[k] || "#58a6ff";
    const n = agents[k];
    const star = oi.has(k) ? "★ " : "";
    const tip = n + " " + k + " commit" + (n === 1 ? "" : "s") +
      (oi.has(k) ? " — including the first-integration commit" : "");
    return '<span class="badge" data-tip="' + esc(tip) + '" style="color:' + c + ';border-color:' + c + '55">' +
      star + esc(k) + ' <span class="muted">' + n + '</span></span>';
  }).join(" ");
}

// Tiny inline-SVG sparkline from an array of cumulative counts. When month and
// as-of metadata are available, x positions use elapsed time rather than equal
// category widths, including the partial current month.
function sparkline(values, w, h, color, months, asOf) {
  w = w || 240; h = h || 34; color = color || "#76b900";
  if (!values || values.length < 2) return '<svg class="spark"></svg>';
  const max = Math.max.apply(null, values), min = Math.min.apply(null, values);
  const span = (max - min) || 1;
  const timeline = monthlyTimeline(months, asOf);
  const useTimeline = timeline.length === values.length &&
    timeline[timeline.length - 1].timestamp > timeline[0].timestamp;
  const firstTimestamp = useTimeline ? timeline[0].timestamp : 0;
  const timestampSpan = useTimeline
    ? timeline[timeline.length - 1].timestamp - firstTimestamp
    : 1;
  const step = w / (values.length - 1);
  const pts = values.map(function (v, i) {
    const x = useTimeline
      ? (timeline[i].timestamp - firstTimestamp) / timestampSpan * w
      : i * step;
    const y = h - 2 - ((v - min) / span) * (h - 4);
    return x.toFixed(1) + "," + y.toFixed(1);
  }).join(" ");
  return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
    '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" points="' + pts + '"/></svg>';
}

function qs(name) { return new URLSearchParams(location.search).get(name); }
function esc(s) { return (s == null ? "" : String(s)).replace(/[&<>"']/g, function (c) {
  return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

// Raw-data download (REQ-03). toCSV builds RFC-4180 CSV from an array of objects;
// downloadFile triggers a client-side download (no server needed).
function toCSV(headers, records) {
  const cell = function (v) {
    if (Array.isArray(v)) v = v.join("; ");
    v = (v == null ? "" : String(v));
    if (/^[\u0000-\u0020]*[=+\-@]/.test(v)) v = "'" + v;
    return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  };
  return [headers.join(",")].concat(records.map(function (row) {
    return headers.map(function (h) { return cell(row[h]); }).join(",");
  })).join("\n");
}
function downloadFile(filename, text, mime) {
  const blob = new Blob([text], { type: (mime || "text/plain") + ";charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
}

// Show the temporary data-coverage notice once per browser profile. The key is
// versioned so a materially different future notice can be shown once as well.
(function initCoverageNotice() {
  if (typeof window === "undefined" || typeof document === "undefined") return;

  const noticeKey = "cdi:data-coverage-notice:2026-08-10:v1";

  function reserveNotice() {
    const storageNames = ["localStorage", "sessionStorage"];
    for (let i = 0; i < storageNames.length; i += 1) {
      try {
        const storage = window[storageNames[i]];
        if (storage.getItem(noticeKey)) return false;
        storage.setItem(noticeKey, "seen");
        return true;
      } catch (_) {
        // Storage can be unavailable in restrictive/private browser contexts.
      }
    }
    return true;
  }

  function showCoverageNotice() {
    if (!reserveNotice()) return;

    const previousFocus = document.activeElement;
    const overlay = document.createElement("div");
    overlay.className = "coverage-notice-overlay";

    const dialog = document.createElement("section");
    dialog.className = "coverage-notice";
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "coverage-notice-title");
    dialog.setAttribute("aria-describedby", "coverage-notice-description coverage-notice-timing");

    const title = document.createElement("h2");
    title.id = "coverage-notice-title";
    title.textContent = "Data coverage notice";

    const description = document.createElement("p");
    description.id = "coverage-notice-description";
    description.textContent = "The dashboard currently reflects a snapshot generated August 3, 2026. Additional libraries are currently being onboarded and validated. Regular weekly updates are temporarily delayed during this onboarding period.";

    const timing = document.createElement("p");
    timing.id = "coverage-notice-timing";
    timing.className = "coverage-notice-timing";
    timing.textContent = "We expect weekly refreshes to resume around August 14, though validation may extend through August 17.";

    const close = document.createElement("button");
    close.className = "coverage-notice-close";
    close.type = "button";
    close.setAttribute("aria-label", "Close data coverage notice");
    close.textContent = "\u00d7";

    function dismiss() {
      document.removeEventListener("keydown", onKeydown);
      document.body.classList.remove("coverage-notice-open");
      overlay.remove();
      if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
    }

    function onKeydown(event) {
      if (event.key === "Escape") dismiss();
      if (event.key === "Tab") {
        event.preventDefault();
        close.focus();
      }
    }

    close.addEventListener("click", dismiss);
    dialog.appendChild(title);
    dialog.appendChild(description);
    dialog.appendChild(timing);
    dialog.appendChild(close);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    document.body.classList.add("coverage-notice-open");
    document.addEventListener("keydown", onKeydown);
    close.focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", showCoverageNotice, { once: true });
  } else {
    showCoverageNotice();
  }
})();

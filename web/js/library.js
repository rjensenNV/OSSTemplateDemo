// Library detail: key takeaways, adoption time-series, sortable/filterable repo table, download dialog.
(function () {
  const id = qs("id");
  let LIB = null, ALLLIBS = [], REPOS = [], TS = null, ASOF = null, BOOT = false, ISPY = false, HANDLE = null;
  // Middle adoption band label/tooltip — varies by library type: Python libs =
  // "Declared" (dep manifest), NVPL = "Build-integrated" (links/selects NVPL via
  // CMake/compat API), other C++ = "Bundled" (ships an SDK copy).
  let CONFLABEL = "Integration", MIDLABEL = "Bundled", MIDDEF = "ships a copy of the SDK; use unconfirmed", MIDTIP = "";
  let CIT = null, CITROOT = null, citChartInst = null, RP = {}, CIT_LOADING = null;   // REQ-07 research citations (RP = repo→paper map)
  let visibleCitationLimit = 200, citationLoadError = null;
  let sortKey = "first_integration", sortDir = -1;   // default: newest first (▼)
  let visibleRepoLimit = 200;
  const expandedOps = {};   // full_name -> show all operators

  // Only emit http(s) links — guards against a malformed/non-http html_url ever
  // producing a javascript:-scheme anchor (defensive; GitHub data is https today).
  function safeUrl(u) { return /^https?:\/\//i.test(u || "") ? u : ""; }

  // Filesystem-safe local timestamp (YYYYMMDD-HHMMSS) so each download is distinct.
  function stamp() {
    const d = new Date(), p = function (n) { return String(n).padStart(2, "0"); };
    return "" + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" +
      p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  function libEntry(repo) {
    // V2 library shards carry an already-projected, single-library entry.
    const direct = (repo.libraries || []).find(function (e) { return e.library_id === id; });
    if (direct) return direct;
    // Component sub-library pages (NVPL BLAS/FFT/…) have no own per-repo entry — they project
    // the PARENT's entry, filtered to repos whose parent operators include this component's label.
    // Confirmed rows use the precise per-component date from component_detail when present, else
    // the parent's family date; classification stays the parent's (a Backend repo shows Backend).
    if (LIB && LIB.parent_id && LIB.projected_from_parent) {
      const pe = (repo.libraries || []).find(function (e) { return e.library_id === LIB.parent_id; });
      if (!pe) return null;
      const label = LIB.component_label;
      if ((pe.operators || []).indexOf(label) < 0) return null;
      const cd = (pe.component_detail || {})[label] || {};
      return {
        library_id: LIB.id,
        classification: pe.classification,
        language: pe.language,
        first_integration: cd.first_integration || pe.first_integration,
        first_integration_commit: cd.first_integration_commit || pe.first_integration_commit,
        ai_on_integration_commit: (cd.ai_on_integration_commit != null) ? cd.ai_on_integration_commit : pe.ai_on_integration_commit,
        ai_on_integration_agents: cd.ai_on_integration_agents || pe.ai_on_integration_agents || [],
        operators: [label],
        is_new: pe.is_new
      };
    }
    return (repo.libraries || []).find(function (e) { return e.library_id === id; });
  }

  // ---- Components section (parent page only): mini-cards linking to each child sub-library ----
  function renderComponents() {
    const kids = ALLLIBS.filter(function (l) { return l.parent_id === id; });
    const h = document.getElementById("components-h");
    const grid = document.getElementById("components");
    if (!kids.length) { return; }
    h.style.display = ""; grid.style.display = "";
    kids.sort(function (a, b) { return (b.headline_count || 0) - (a.headline_count || 0); });
    grid.innerHTML = kids.map(function (l) {
      const coverage = l.classification_coverage || {};
      const big = (l.headline_count != null)
        ? l.headline_count
        : (l.confirmed_count != null ? l.confirmed_count : null);
      const confirmed = coverage.confirmed === "not_evaluated"
        ? "#include not evaluated"
        : (l.confirmed_count || 0) + " #include";
      const bundled = coverage.bundled === "not_evaluated"
        ? "backend not evaluated"
        : (l.bundled_count || 0) + " backend";
      const sub = confirmed + (l.adoption_counts_build ? " · " + bundled : "");
      return '<a class="comp-card" href="library.html?id=' + esc(l.id) + '">' +
        '<div class="comp-row"><span class="comp-name">' + esc(l.name) + '</span>' +
        '<span class="badge flat">since ' + esc(l.released_on) + '</span></div>' +
        '<div class="comp-big">' +
        (big == null
          ? 'Metric pending<small>not evaluated</small>'
          : big + '<small>integrations</small>') +
        '</div>' +
        '<div class="muted" style="font-size:12px">' + sub + '</div>' +
        sparkline(l.sparkline, 200, 40, null, l.sparkline_months, l.timeseries_as_of || ASOF) + '</a>';
    }).join("");
  }

  // ---- Key takeaways cards (auto-updated each refresh from aggregate()) ----
  function takeaways() {
    // % growth in new integrations: month-over-month and year-over-year.
    function pct(cur, prev) {
      if (prev === 0) return cur === 0 ? { txt: "±0%", cls: "flat" } : { txt: "▲ new", cls: "up" };
      const g = Math.round((cur - prev) / prev * 100);
      if (g > 0) return { txt: "▲ +" + g + "%", cls: "up" };
      if (g < 0) return { txt: "▼ " + Math.abs(g) + "%", cls: "down" };
      return { txt: "±0%", cls: "flat" };
    }
    function card(label, cur, prev) {
      const p = pct(cur, prev);
      return '<div class="tk-card"><div class="tk-label">' + label + "</div>" +
        '<div class="tk-num tk-' + p.cls + '">' + p.txt + "</div></div>";
    }
    function pending(label, tip) {
      return '<div class="tk-card tk-pending"' + (tip ? ' data-tip="' + esc(tip) + '"' : '') +
        '><div class="tk-label">' + label + '</div><div class="tk-num muted">—</div></div>';
    }
    // Repo-integration growth is null when the library is younger than a full PRIOR comparison
    // window (or the collector couldn't compute it) — show the pending "—" card, never a fake
    // 0%/▲new. Mirrors the Research-usage cards. Auto-fills once enough history since release.
    const relNote = LIB.released_on ? " since release (" + LIB.released_on + ")" : "";
    const rep90 = LIB.growth_90d
      ? card("Repo integrations · last 90 days", LIB.growth_90d.current || 0, LIB.growth_90d.prev || 0)
      : pending("Repo integrations · last 90 days", "awaiting a full 90-day comparison window" + relNote);
    const rep365 = LIB.growth_365d
      ? card("Repo integrations · last 365 days", LIB.growth_365d.current || 0, LIB.growth_365d.prev || 0)
      : pending("Repo integrations · last 365 days", "awaiting a full 365-day comparison window" + relNote);
    const cit90 = (CIT && CIT.growth_90d)
      ? card("Research usage · last 90 days", CIT.growth_90d.current || 0, CIT.growth_90d.prev || 0)
      : pending("Research usage · last 90 days");
    const cit365 = (CIT && CIT.growth_365d)
      ? card("Research usage · last 365 days", CIT.growth_365d.current || 0, CIT.growth_365d.prev || 0)
      : pending("Research usage · last 365 days");
    document.getElementById("takeaways").innerHTML = rep90 + rep365 + cit90 + cit365;
  }

  // ---- Research citations view (REQ-07) ----
  let citSortKey = "cited_by", citSortDir = -1;

  function citHeader() {
    const counts = document.getElementById("cit-counts");
    const quality = document.getElementById("cit-quality");
    if (!CIT) {
      counts.innerHTML = '<span class="muted">no citation data</span>';
      quality.textContent = "Citation coverage is unavailable.";
      return;
    }
    const conf = CIT.confidence === "medium"
      ? ' <span class="confidence-note">· lower-precision name (see caveats)</span>' : '';
    counts.innerHTML = '<b>' + (CIT.total || 0) + '</b> research mentions' + conf;
    const coverage = CIT.coverage || {};
    const notes = [];
    // Citation freshness/completeness is operator quality metadata. In particular,
    // best-effort PDF repository-link extraction can be incomplete even when every
    // accepted OpenAlex paper is present, so those states are not user-facing badges.
    if (CIT.papers_capped || coverage.capped) {
      notes.push('<span class="badge warn">paper sample capped</span>');
    }
    const displayed = (CIT.displayed_papers_count != null)
      ? CIT.displayed_papers_count
      : ((CIT.papers || []).length);
    if (CIT.papers_capped || displayed !== (CIT.total || 0)) {
      notes.push('<span>Showing ' + displayed + ' paper records; the headline is the source total.</span>');
    }
    quality.innerHTML = notes.join(" ");
  }

  function citChart() {
    const el = document.getElementById("cit-chart");
    if (citChartInst) { citChartInst.resize(); return; }   // already drawn; just fit
    const pts = (CIT && CIT.monthly) || [];
    if (!pts.length) { el.style.display = "none"; return; }
    citChartInst = echarts.init(el, null, { renderer: "canvas" });
    const months = pts.map(function (p) { return p.month; });
    const cum = pts.map(function (p) { return p.cumulative || 0; });
    const timeline = monthlyTimeline(months, CIT.as_of || (CIT.coverage || {}).as_of || ASOF);
    const cumulativeSeries = cum.map(function (value, index) {
      return [timeline[index].timestamp, value];
    });
    citChartInst.setOption({
      backgroundColor: "transparent", textStyle: { color: "#8b949e" },
      tooltip: {
        trigger: "axis", backgroundColor: "#1c2025", borderColor: "#2a2f36", textStyle: { color: "#e6e9ed" },
        formatter: function (ps) {
          const p = ps[0], value = Array.isArray(p.value) ? p.value[1] : p.value;
          const timestamp = Array.isArray(p.value) ? p.value[0] : p.axisValue;
          return timelineTooltipLabel(timestamp, timeline) + "<br/>" + p.marker +
            "<b>" + (value || 0) + "</b> papers (cumulative)";
        }
      },
      legend: { data: ["Research mentions"], textStyle: { color: "#e6e9ed" }, top: 0, icon: "roundRect" },
      grid: { left: 44, right: 20, top: 36, bottom: 64 },
      xAxis: { type: "time", boundaryGap: false,
        axisLine: { lineStyle: { color: "#2a2f36" } },
        axisLabel: { color: "#8b949e", formatter: timelineAxisLabel } },
      yAxis: { type: "value", minInterval: 1, splitLine: { lineStyle: { color: "#1c2025" } }, axisLabel: { color: "#8b949e" } },
      dataZoom: [
        { type: "inside", start: 0, end: 100 },
        { type: "slider", start: 0, end: 100, height: 22, bottom: 18, borderColor: "#2a2f36",
          fillerColor: "rgba(118,185,0,0.12)", handleStyle: { color: "#76b900" }, textStyle: { color: "#8b949e" } }
      ],
      toolbox: { right: 10, top: 0, iconStyle: { borderColor: "#8b949e" },
        feature: { dataZoom: { yAxisIndex: "none" }, restore: {}, saveAsImage: { backgroundColor: "#0b0d0f" } } },
      series: [{ name: "Research mentions", type: "line", symbol: "none", showSymbol: false,
        color: "#76b900", lineStyle: { width: 1.5 }, areaStyle: { color: "rgba(118,185,0,0.30)" }, data: cumulativeSeries }]
    });
    window.addEventListener("resize", function () { if (citChartInst) citChartInst.resize(); });
  }

  function citList() {
    const q = document.getElementById("cit-search").value.toLowerCase().trim();
    const f = document.getElementById("cit-filter").value;
    let list = ((CIT && CIT.papers) || []).slice();
    if (f === "code") list = list.filter(function (p) { return p.code_available; });
    if (q) list = list.filter(function (p) {
      return (p.title || "").toLowerCase().indexOf(q) >= 0 || (p.venue || "").toLowerCase().indexOf(q) >= 0 ||
        (p.repo || "").toLowerCase().indexOf(q) >= 0; });
    list.sort(function (a, b) {
      let va, vb;
      if (citSortKey === "cited_by") { va = a[citSortKey] || 0; vb = b[citSortKey] || 0; }
      else if (citSortKey === "publication_date") {
        va = a.publication_date || (a.year ? String(a.year) + "-01-01" : "");
        vb = b.publication_date || (b.year ? String(b.year) + "-01-01" : "");
      } else { va = (a[citSortKey] || "").toString().toLowerCase(); vb = (b[citSortKey] || "").toString().toLowerCase(); }
      if (va < vb) return -1 * citSortDir; if (va > vb) return 1 * citSortDir; return 0;
    });
    return list;
  }

  function citPapers() {
    const tb = document.querySelector("#papers tbody");
    const empty = document.getElementById("cit-empty");
    const all = (CIT && CIT.papers) || [];
    const list = citList();
    const hasUnloadedParts = !!(
      HANDLE && HANDLE.mode === "v2" &&
      HANDLE.nextCitationPart < HANDLE.citationParts.length
    );
    if (!list.length) {
      tb.innerHTML = ""; empty.style.display = "block";
      const message = all.length
        ? "No papers match."
        : ((CIT && (CIT.total || 0) > 0)
          ? (hasUnloadedParts
            ? "No paper records in the loaded page."
            : "No paper records are available in the displayed sample.")
          : "No research mentions found.");
      empty.innerHTML = (citationLoadError
        ? '<span class="badge warn">' + esc(citationLoadError) + '</span> '
        : "") + esc(message) + (hasUnloadedParts
        ? ' <button type="button" id="cit-more">Load next research page</button>'
        : "");
      const emptyMore = document.getElementById("cit-more");
      if (emptyMore) emptyMore.addEventListener("click", loadMoreCitations);
      return;
    }
    const visible = list.slice(0, visibleCitationLimit);
    tb.innerHTML = visible.map(function (p) {
      const u = p.doi ? "https://doi.org/" + p.doi : (p.oa_url || "");
      const title = u ? '<a href="' + esc(safeUrl(u)) + '" target="_blank" rel="noopener">' + esc(p.title || "(untitled)") + '</a>'
                      : esc(p.title || "(untitled)");
      let code;
      if (p.repo) {
        code = '<a class="repo-name" href="' + esc(safeUrl(p.repo_url || ("https://github.com/" + p.repo))) + '" target="_blank" rel="noopener">' + esc(p.repo) + '</a>' +
          ' <a href="#" class="jump-btn" data-repo="' + esc(p.repo) + '" data-tip="show this repo in the GitHub adoption table">↳ adoption</a>';
      } else {
        code = '<span class="muted">—</span>';
      }
      return '<tr><td>' + title + '</td>' +
        '<td class="num">' + (p.publication_date ? fmtDate(p.publication_date) : (p.year || "—")) + '</td>' +
        '<td>' + esc(p.venue || "—") + '</td>' +
        '<td class="num">' + (p.cited_by || 0) + '</td>' +
        '<td>' + code + '</td></tr>';
    }).join("");
    const hasHiddenLoadedRows = visibleCitationLimit < list.length;
    if (hasHiddenLoadedRows || hasUnloadedParts || citationLoadError) {
      empty.style.display = "block";
      empty.innerHTML = (citationLoadError
        ? '<span class="badge warn">' + esc(citationLoadError) + '</span> '
        : "") + "Showing " + visible.length + " of " +
        ((CIT && CIT.displayed_papers_count) || all.length) +
        " paper records" + (hasUnloadedParts ? " · additional pages load on demand" : "") +
        (hasHiddenLoadedRows || hasUnloadedParts
          ? ' <button type="button" id="cit-more">' +
            (hasHiddenLoadedRows ? "Show more papers" : "Load next research page") +
            "</button>"
          : "");
      const more = document.getElementById("cit-more");
      if (more) more.addEventListener("click", loadMoreCitations);
    } else {
      empty.style.display = "none";
      empty.textContent = "";
    }
  }

  function loadMoreCitations() {
    const button = document.getElementById("cit-more");
    if (button) button.disabled = true;
    citationLoadError = null;
    const filtered = citList().length;
    const operation = visibleCitationLimit < filtered
      ? Promise.resolve([])
      : CXITData.loadNextCitationPart(HANDLE);
    operation.then(function () {
      visibleCitationLimit += 200;
      CIT = HANDLE.citationResult && HANDLE.citationResult.citation;
      RP = (CIT && CIT.repo_papers) || {};
      rows(); citPapers();
    }).catch(function (error) {
      citationLoadError = "Could not load more research data: " + error.message;
      citPapers();
    });
  }

  function citSetArrows() {
    Array.prototype.forEach.call(document.querySelectorAll("#papers th"), function (h) {
      h.innerHTML = h.innerHTML.replace(/ <span class="arrow">[^<]*<\/span>/, "");
      if (h.dataset.k === citSortKey) h.innerHTML += ' <span class="arrow">' + (citSortDir < 0 ? "▼" : "▲") + "</span>";
    });
  }
  function citHeaders() {
    Array.prototype.forEach.call(document.querySelectorAll("#papers th"), function (th) {
      th.addEventListener("click", async function () {
        const k = th.dataset.k; if (!k) return;
        try {
          await ensureAllCitations();
        } catch (_error) {
          return;
        }
        if (citSortKey === k) citSortDir *= -1;
        else { citSortKey = k; citSortDir = (k === "title" || k === "venue" || k === "repo") ? 1 : -1; }
        visibleCitationLimit = 200;
        citSetArrows(); citPapers();
      });
    });
    citSetArrows();
  }

  // jump from a paper's repo back to the GitHub adoption table, filtered + flashed.
  async function jumpToRepo(repo) {
    const ad = document.querySelector('.tab-btn[data-view="adoption"]');
    if (ad) ad.click();
    if (HANDLE) {
      try {
        await CXITData.loadAllRepositoryParts(HANDLE);
        REPOS = HANDLE.repos;
      } catch (error) {
        const status = document.getElementById("repo-part-status");
        if (status) {
          status.textContent = "Could not load all repositories: " + error.message;
        }
      }
    }
    const kl = document.getElementById("klass"); if (kl) kl.value = "all";
    const s = document.getElementById("search"); s.value = repo;
    visibleRepoLimit = 200;
    rows(); updateRepoParts();
    setTimeout(function () {
      const tr = document.querySelector("#repos tbody tr");
      if (tr) { tr.scrollIntoView({ behavior: "smooth", block: "center" });
        tr.classList.add("flash"); setTimeout(function () { tr.classList.remove("flash"); }, 2200); }
    }, 60);
  }

  function citCaveats() {
    const cav = (CITROOT && CITROOT.caveats) || [];
    let items = cav.map(function (c) { return "<li>" + esc(c) + "</li>"; }).join("");
    if (CIT && CIT.query) items += "<li>Query: <code>" + esc(CIT.query) + "</code> (OpenAlex full-text search).</li>";
    if (CIT && (CIT.papers_capped || (CIT.coverage || {}).capped)) {
      items += "<li>The headline uses the OpenAlex source total; the paper table and monthly series are a capped display sample.</li>";
    }
    items += "<li>The current month is partial.</li>";
    document.getElementById("cit-caveats").innerHTML = "<h3>Method &amp; caveats</h3><ul>" + items + "</ul>";
  }

  // ---- Citations download dialog (timeframe + columns), mirroring the integrations one ----
  const CIT_DL_COLUMNS = [
    { key: "title", label: "Paper" }, { key: "year", label: "Year" }, { key: "venue", label: "Venue" },
    { key: "cited_by", label: "Cited by" }, { key: "doi", label: "DOI" }, { key: "oa_url", label: "OA URL" },
    { key: "repo", label: "Code repo" }, { key: "publication_date", label: "Published date" }
  ];
  function citRecordFor(p) {
    return { title: p.title, year: p.year, venue: p.venue, cited_by: p.cited_by || 0,
      doi: p.doi || "", oa_url: p.oa_url || "", repo: p.repo || "", publication_date: p.publication_date || "" };
  }
  async function openCitDialog(fmt) {
    await ensureAllCitations();
    document.querySelector('input[name="citdlfmt"][value="' + fmt + '"]').checked = true;
    document.getElementById("cit-dl-lib").textContent = LIB ? LIB.name : "";
    const dates = ((CIT && CIT.papers) || []).map(function (p) { return p.publication_date; }).filter(Boolean).sort();
    document.getElementById("cit-dl-from").value = dates.length ? dates[0] : "";
    document.getElementById("cit-dl-to").value = dates.length ? dates[dates.length - 1] : "";
    document.getElementById("cit-dl-cols").innerHTML = CIT_DL_COLUMNS.map(function (c) {
      return '<label><input type="checkbox" class="cit-dl-col" value="' + c.key + '" checked> ' + esc(c.label) + "</label>"; }).join("");
    document.getElementById("cit-dl-modal").style.display = "flex";
  }
  function closeCitDialog() { document.getElementById("cit-dl-modal").style.display = "none"; }
  function doCitDownload() {
    const fmt = document.querySelector('input[name="citdlfmt"]:checked').value;
    const from = document.getElementById("cit-dl-from").value, to = document.getElementById("cit-dl-to").value;
    const cols = Array.prototype.map.call(document.querySelectorAll(".cit-dl-col:checked"), function (c) { return c.value; });
    if (!cols.length) { return; }
    let list = ((CIT && CIT.papers) || []).filter(function (p) {
      const d = p.publication_date;
      if (!d) return true;                    // undated papers can't be date-filtered — always include
      return (!from || d >= from) && (!to || d <= to);
    });
    const records = list.map(citRecordFor).map(function (rec) { const o = {}; cols.forEach(function (k) { o[k] = rec[k]; }); return o; });
    const base = "cuda-x-di_" + (LIB ? LIB.id : "library") + "_citations_" + stamp();
    if (fmt === "json") downloadFile(base + ".json", JSON.stringify(records, null, 2), "application/json");
    else downloadFile(base + ".csv", toCSV(cols, records), "text/csv");
    closeCitDialog();
  }

  function setupTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    Array.prototype.forEach.call(tabs, function (btn) {
      btn.addEventListener("click", function () {
        const view = btn.dataset.view;
        Array.prototype.forEach.call(tabs, function (b) { b.classList.toggle("active", b === btn); });
        document.getElementById("view-adoption").style.display = (view === "adoption") ? "" : "none";
        document.getElementById("view-citations").style.display = (view === "citations") ? "" : "none";
        if (view === "citations") {
          ensureCitations().then(function () {
            citChart();   // lazy data + chart init; chart needs a visible width
          }).catch(function () { /* ensureCitations renders the retryable error */ });
        }
      });
    });
    document.querySelector("#papers tbody").addEventListener("click", function (ev) {
      const t = ev.target.closest(".jump-btn");
      if (!t) return; ev.preventDefault(); jumpToRepo(t.dataset.repo);
    });
  }

  function ensureCitations() {
    if (CIT_LOADING) return CIT_LOADING;
    let loading;
    loading = CXITData.loadCitations(HANDLE).then(function (result) {
      CITROOT = result.root;
      CIT = result.citation;
      RP = (CIT && CIT.repo_papers) || {};
      citationLoadError = null;
      takeaways(); citHeader(); citPapers(); citCaveats(); rows();
    }).catch(function (error) {
      citationLoadError = "Could not load research data: " + error.message;
      document.getElementById("cit-counts").innerHTML =
        '<span class="muted">Could not load research data (' + esc(error.message) +
        ')</span> <button type="button" id="cit-retry">Retry</button>';
      const retry = document.getElementById("cit-retry");
      if (retry) {
        retry.addEventListener("click", function () {
          retry.disabled = true;
          ensureCitations().catch(function () {});
        });
      }
      throw error;
    }).finally(function () {
      if (CIT_LOADING === loading) CIT_LOADING = null;
    });
    CIT_LOADING = loading;
    return loading;
  }

  async function ensureAllCitations() {
    await ensureCitations();
    try {
      CIT = await CXITData.loadAllCitationParts(HANDLE);
      RP = (CIT && CIT.repo_papers) || {};
      citationLoadError = null;
      rows(); citPapers();
      return CIT;
    } catch (error) {
      citationLoadError = "Could not load all research data: " + error.message;
      citPapers();
      throw error;
    }
  }

  function chart() {
    const el = document.getElementById("chart");
    const c = echarts.init(el, null, { renderer: "canvas" });
    const pts = (TS && TS.points) || [];
    const MID = MIDLABEL;
    const CONF = CONFLABEL;
    const months = pts.map(function (p) { return p.month; });
    const timeline = monthlyTimeline(months, (TS && TS.as_of) || LIB.timeseries_as_of || ASOF);
    const conf = pts.map(function (p) { return p.confirmed || 0; });
    const bundled = pts.map(function (p) { return p.bundled || 0; });
    const targeted = pts.map(function (p) { return p.targeted || 0; });
    // Order + visibility by each band's COUNT (not the dated-cumulative line height,
    // which differs when entries are undated): biggest count on TOP, smallest at the
    // BOTTOM (top->bottom = biggest->smallest count), and drop any zero-count band
    // entirely (e.g. NVPL's Targeted = 0). ECharts draws the FIRST series at the bottom,
    // so sort ASCENDING by count. Colors are fixed per class; only the order varies.
    const _bands = [
      { name: CONF,          n: (LIB.confirmed_count || 0), color: "#76b900", lw: 1.5, area: "rgba(118,185,0,0.45)", data: conf },
      { name: MID,           n: (LIB.bundled_count || 0),   color: "#d29922", lw: 1,   area: "rgba(210,153,34,0.30)", data: bundled },
      { name: "Targeted",    n: (LIB.targeted_count || 0),  color: "#8b949e", lw: 1,   area: "rgba(139,148,158,0.22)", data: targeted }
    ];
    const _nz = _bands.filter(function (s) { return s.n > 0; });
    const seriesDefs = (_nz.length ? _nz : _bands)
      .sort(function (a, b) { return a.n - b.n; })   // smallest count => bottom; biggest count => top
      .map(function (s) {
        return { name: s.name, type: "line", stack: "total", symbol: "none", showSymbol: false,
                 color: s.color, lineStyle: { width: s.lw }, areaStyle: { color: s.area },
                 data: s.data.map(function (value, index) { return [timeline[index].timestamp, value]; }) };
      });
    // Legend lists only the bands actually shown, in a stable semantic order.
    const legendData = [CONF, MID, "Targeted"].filter(function (n) {
      return seriesDefs.some(function (s) { return s.name === n; });
    });
    c.setOption({
      backgroundColor: "transparent",
      textStyle: { color: "#8b949e" },
      tooltip: {
        trigger: "axis", backgroundColor: "#1c2025", borderColor: "#2a2f36", textStyle: { color: "#e6e9ed" },
        formatter: function (ps) {
          const defs = { Integration: "own source uses it", "Direct #include": "own source directly includes an NVPL header", Targeted: "code/build references it; no source include" };
          defs[MID] = MIDDEF;
          const timestamp = ps.length && Array.isArray(ps[0].value) ? ps[0].value[0] : null;
          let total = 0, s = ps.length ? timelineTooltipLabel(timestamp, timeline) + "<br/>" : "";
          ps.forEach(function (p) {
            const value = Array.isArray(p.value) ? p.value[1] : p.value;
            total += value || 0;
            s += p.marker + p.seriesName + ": <b>" + (value || 0) + '</b> <span style="color:#8b949e">— ' + (defs[p.seriesName] || "") + "</span><br/>";
          });
          return s + "<b>Total adopters: " + total + "</b>";
        }
      },
      legend: { data: legendData, textStyle: { color: "#e6e9ed" }, top: 0, icon: "roundRect" },
      grid: { left: 44, right: 20, top: 36, bottom: 64 },
      xAxis: { type: "time", boundaryGap: false,
        axisLine: { lineStyle: { color: "#2a2f36" } },
        axisLabel: { color: "#8b949e", formatter: timelineAxisLabel } },
      yAxis: { type: "value", minInterval: 1, splitLine: { lineStyle: { color: "#1c2025" } },
        axisLabel: { color: "#8b949e" } },
      dataZoom: [
        { type: "inside", start: 0, end: 100 },
        { type: "slider", start: 0, end: 100, height: 22, bottom: 18,
          borderColor: "#2a2f36", fillerColor: "rgba(118,185,0,0.12)",
          handleStyle: { color: "#76b900" }, textStyle: { color: "#8b949e" } }
      ],
      toolbox: { right: 10, top: 0, iconStyle: { borderColor: "#8b949e" },
        feature: { dataZoom: { yAxisIndex: "none" }, restore: {}, saveAsImage: { backgroundColor: "#0b0d0f" } } },
      series: seriesDefs
    });
    window.addEventListener("resize", function () { c.resize(); });
  }

  function currentList() {
    const q = document.getElementById("search").value.toLowerCase().trim();
    const klass = document.getElementById("klass").value;
    let list = REPOS.map(function (r) { return { r: r, e: libEntry(r) }; }).filter(function (x) { return x.e; });
    if (klass !== "all") list = list.filter(function (x) { return x.e.classification === klass; });
    if (q) list = list.filter(function (x) { return x.r.full_name.toLowerCase().indexOf(q) >= 0 ||
      (x.r.description || "").toLowerCase().indexOf(q) >= 0; });
    list.sort(function (a, b) {
      let va, vb;
      if (sortKey === "first_integration") { va = a.e.first_integration || ""; vb = b.e.first_integration || ""; }
      else if (sortKey === "type") { va = a.e.classification || ""; vb = b.e.classification || ""; }
      else if (sortKey === "ai") { va = Object.keys(a.r.ai_agents || {}).length; vb = Object.keys(b.r.ai_agents || {}).length; }
      else if (sortKey === "operators") { va = (a.e.operators || []).length; vb = (b.e.operators || []).length; }
      else if (sortKey === "stars" || sortKey === "forks") { va = a.r[sortKey] || 0; vb = b.r[sortKey] || 0; }
      else if (sortKey === "language") { va = (a.e.language || a.r.language || "").toLowerCase(); vb = (b.e.language || b.r.language || "").toLowerCase(); }
      else { va = (a.r[sortKey] || "").toString().toLowerCase(); vb = (b.r[sortKey] || "").toString().toLowerCase(); }
      if (va < vb) return -1 * sortDir; if (va > vb) return 1 * sortDir; return 0;
    });
    return list;
  }

  function repositoryFiltersActive() {
    return document.getElementById("search").value.trim() !== "" ||
      document.getElementById("klass").value !== "all";
  }

  function rows() {
    const all = currentList();
    const list = all.slice(0, visibleRepoLimit);
    const tb = document.querySelector("#repos tbody");
    const empty = document.getElementById("empty");
    if (!list.length) { tb.innerHTML = ""; empty.style.display = "block"; empty.textContent = "No repositories match."; return; }
    empty.style.display = "none";
    tb.innerHTML = list.map(function (x) {
      const r = x.r, e = x.e;
      const TYPE = {
        confirmed: ["badge tier", CONFLABEL.toLowerCase(), CONFLABEL + " — the repo's own source uses the library (a real #include, or a Python import of its namespace)."],
        bundled:   ["badge warn", MIDLABEL.toLowerCase(), MIDTIP],
        targeted:  ["badge flat", "targeted",    "Targeted — the repo's own code or build references the library without a direct source include/import."]
      };
      const tp = TYPE[e.classification] || ["badge flat", e.classification, e.classification];
      const desc = r.description ? '<div class="repo-desc">' + esc(r.description) + '</div>' : '';
      const repoUrl = safeUrl(r.html_url);
      // paper icon (REQ-07): this repo is referenced by a research paper we tracked
      const pap = RP[r.full_name];
      const paperIcon = pap ? ' <a class="paper-icon" href="' + esc(safeUrl(pap.doi ? "https://doi.org/" + pap.doi : (pap.oa_url || ""))) +
        '" target="_blank" rel="noopener" data-tip="linked research paper: ' + esc(pap.title || "") + '">📄</a>' : '';
      // Adopted ↗ — links to the first-integration commit (scheme-validated).
      const sha = e.first_integration_commit;
      const commitUrl = sha ? safeUrl((r.html_url || ("https://github.com/" + r.full_name)) + "/commit/" + sha) : "";
      const dateCell = e.first_integration
        ? (commitUrl
            ? '<a class="commit-link" href="' + esc(commitUrl) + '" target="_blank" rel="noopener" data-tip="opens the first-integration commit ' + esc(sha) + '">' + fmtDate(e.first_integration) + ' ↗</a>'
            : fmtDate(e.first_integration))
        : "—";
      // Operators — truncate to 6, "+N" expands the row to list every operator.
      const ops = e.operators || [];
      let opsCell;
      if (!ops.length) opsCell = '<span class="muted">—</span>';
      else if (expandedOps[r.full_name]) opsCell = '<span class="ops">' + esc(ops.join(", ")) +
        '</span> <a href="#" class="ops-toggle" data-fn="' + esc(r.full_name) + '">− less</a>';
      else if (ops.length > 6) opsCell = '<span class="ops">' + esc(ops.slice(0, 6).join(", ")) +
        '</span> <a href="#" class="ops-toggle" data-fn="' + esc(r.full_name) + '">+' + (ops.length - 6) + '</a>';
      else opsCell = '<span class="ops">' + esc(ops.join(", ")) + '</span>';
      return '<tr class="repo' + (e.is_new ? " is-new" : "") + '">' +
        '<td>' + (repoUrl
            ? '<a class="repo-name" href="' + esc(repoUrl) + '" target="_blank" rel="noopener">' + esc(r.full_name) + '</a>'
            : '<span class="repo-name">' + esc(r.full_name) + '</span>') + paperIcon +
          (e.is_new ? ' <span class="badge new">NEW</span>' : '') + desc + '</td>' +
        '<td><span class="' + tp[0] + '" data-tip="' + esc(tp[2]) + '">' + tp[1] + '</span></td>' +
        '<td class="num">' + (r.stars || 0) + '</td>' +
        '<td class="num">' + (r.forks || 0) + '</td>' +
        '<td>' + esc(e.language || r.language || "—") + '</td>' +
        '<td class="nowrap">' + dateCell + '</td>' +
        '<td class="ops-cell">' + opsCell + '</td>' +
        '<td>' + agentBadges(r.ai_agents, e.ai_on_integration_agents) + '</td>' +
        '</tr>';
    }).join("");
  }

  // ---- Download dialog (timeframe + columns) ----
  const DL_COLUMNS = [
    { key: "full_name", label: "Repository" }, { key: "classification", label: "Type" },
    { key: "first_integration", label: "Date adopted" }, { key: "first_integration_commit", label: "Commit" },
    { key: "stars", label: "Stars" }, { key: "forks", label: "Forks" }, { key: "language", label: "Language" },
    { key: "operators", label: "Operators" }, { key: "ai_agents", label: "AI co-authors" }, { key: "html_url", label: "URL" }
  ];
  function recordFor(x) {
    const r = x.r, e = x.e;
    return { full_name: r.full_name, classification: e.classification,
      first_integration: e.first_integration || "", first_integration_commit: e.first_integration_commit || "",
      stars: r.stars || 0, forks: r.forks || 0, language: e.language || r.language || "",
      operators: e.operators || [], ai_agents: Object.keys(r.ai_agents || {}), html_url: r.html_url || "" };
  }
  async function openDialog(fmt) {
    if (HANDLE) {
      await CXITData.loadAllRepositoryParts(HANDLE);
      REPOS = HANDLE.repos;
      updateRepoParts();
      rows();
    }
    document.querySelector('input[name="dlfmt"][value="' + fmt + '"]').checked = true;
    document.getElementById("dl-lib").textContent = LIB ? LIB.name : "";
    const dates = REPOS.map(libEntry).filter(Boolean).map(function (e) { return e.first_integration; }).filter(Boolean).sort();
    document.getElementById("dl-from").value = dates.length ? dates[0] : "";
    document.getElementById("dl-to").value = dates.length ? dates[dates.length - 1] : "";
    document.getElementById("dl-cols").innerHTML = DL_COLUMNS.map(function (c) {
      return '<label><input type="checkbox" class="dl-col" value="' + c.key + '" checked> ' + esc(c.label) + "</label>"; }).join("");
    document.getElementById("dl-modal").style.display = "flex";
  }

  function updateRepoParts() {
    const button = document.getElementById("repo-more");
    const status = document.getElementById("repo-part-status");
    if (!button || !status || !HANDLE || HANDLE.mode !== "v2") {
      if (button) button.style.display = "none";
      if (status) status.textContent = "";
      return;
    }
    const total = (HANDLE.index && HANDLE.index.row_count) || REPOS.length;
    const filtered = currentList().length;
    const remaining = visibleRepoLimit < filtered ||
      HANDLE.nextRepoPart < HANDLE.repoParts.length;
    button.style.display = remaining ? "" : "none";
    button.textContent = visibleRepoLimit < filtered
      ? "Show more repositories"
      : "Load next repository shard";
    if (repositoryFiltersActive()) {
      status.textContent = "Showing " + Math.min(visibleRepoLimit, filtered) +
        " of " + filtered + " matching repositories" +
        (REPOS.length < total ? " · additional shards may contain matches" : "");
    } else {
      status.textContent = "Showing " + Math.min(visibleRepoLimit, filtered) +
        " of " + total + " repositories" +
        (REPOS.length < total ? " · additional shards load on demand" : "");
    }
  }
  function closeDialog() { document.getElementById("dl-modal").style.display = "none"; }
  function doDownload() {
    const fmt = document.querySelector('input[name="dlfmt"]:checked').value;
    const from = document.getElementById("dl-from").value, to = document.getElementById("dl-to").value;
    const cols = Array.prototype.map.call(document.querySelectorAll(".dl-col:checked"), function (c) { return c.value; });
    if (!cols.length) { return; }
    let list = REPOS.map(function (r) { return { r: r, e: libEntry(r) }; }).filter(function (x) { return x.e; });
    list = list.filter(function (x) {
      const d = x.e.first_integration;
      if (!d) return true;                    // undated rows can't be date-filtered — always include
      return (!from || d >= from) && (!to || d <= to);
    });
    const records = list.map(recordFor).map(function (rec) { const o = {}; cols.forEach(function (k) { o[k] = rec[k]; }); return o; });
    // Descriptive + timestamped + distinct, e.g. cuda-x-di_dali_integrations_20260623-161530.csv
    const base = "cuda-x-di_" + (LIB ? LIB.id : "library") + "_integrations_" + stamp();
    if (fmt === "json") downloadFile(base + ".json", JSON.stringify(records, null, 2), "application/json");
    else downloadFile(base + ".csv", toCSV(cols, records), "text/csv");
    closeDialog();
  }

  function setArrows() {
    Array.prototype.forEach.call(document.querySelectorAll("#repos th"), function (h) {
      h.innerHTML = h.innerHTML.replace(/ <span class="arrow">[^<]*<\/span>/, "");
      if (h.dataset.k === sortKey) h.innerHTML += ' <span class="arrow">' + (sortDir < 0 ? "▼" : "▲") + "</span>";
    });
  }
  function headers() {
    Array.prototype.forEach.call(document.querySelectorAll("#repos th"), function (th) {
      th.addEventListener("click", async function () {
        if (HANDLE) {
          await CXITData.loadAllRepositoryParts(HANDLE);
          REPOS = HANDLE.repos;
        }
        const k = th.dataset.k;
        if (sortKey === k) sortDir *= -1;
        else { sortKey = k; sortDir = (k === "full_name" || k === "language" || k === "type") ? 1 : -1; }
        visibleRepoLimit = 200;
        setArrows(); rows(); updateRepoParts();
      });
    });
    setArrows();
  }

  CXITData.loadLibrary(id)
    .then(function (handle) {
      HANDLE = handle;
      const cur = handle.current; TS = handle.timeseries;
      ASOF = (handle.manifest && handle.manifest.generated_at) || cur.generated_at;
      BOOT = cur.is_bootstrap;
      ALLLIBS = handle.libraries || [];
      LIB = handle.library;
      REPOS = handle.repos || [];
      if (!LIB) { document.getElementById("lib-name").textContent = "Unknown library"; return; }
      CONFLABEL = LIB.adoption_counts_build ? "Direct #include" : "Integration";
      ISPY = (LIB.language === "python");
      if (ISPY) {
        MIDLABEL = "Declared";
        MIDDEF = "dependency/Dockerfile names the package; no import found";
        MIDTIP = "Declared — a dependency manifest or Dockerfile names the package, but no import was found in the repo's own source (use unconfirmed).";
      } else if (LIB.bundled_label) {
        MIDLABEL = LIB.bundled_label;   // e.g. "Backend" for NVPL
        MIDDEF = "build links/selects the library, often via a compat API";
        MIDTIP = MIDLABEL + " — the repo's build deliberately links or selects the library, "
          + "commonly through the standard FFTW/CBLAS/LAPACKE compatibility API, or a manifest "
          + "declares an nvpl-* package. A real build-level adoption, distinct from a direct source #include.";
      } else {
        MIDLABEL = "Bundled";
        MIDDEF = "ships a copy of the SDK; use unconfirmed";
        MIDTIP = "Bundled — the repo ships a copy of the library's SDK in its tree, but its own source never includes it (use unconfirmed).";
      }
      const bo = document.querySelector('#klass option[value="bundled"]');
      if (bo) bo.textContent = MIDLABEL + " only";
      const co = document.querySelector('#klass option[value="confirmed"]');
      if (co) co.textContent = CONFLABEL + " only";
      const coverage = LIB.classification_coverage || {};
      ["confirmed", "bundled", "targeted"].forEach(function (classification) {
        if (coverage[classification] !== "not_evaluated") return;
        const option = document.querySelector('#klass option[value="' + classification + '"]');
        if (option) {
          option.disabled = true;
          option.textContent = option.textContent.replace(/ only$/, "") + " — not evaluated";
        }
      });
      document.title = LIB.name + " — CUDA-X Developer Intelligence";
      // Component pages get a breadcrumb back to the parent library.
      if (LIB.parent_id) {
        const parent = ALLLIBS.find(function (l) { return l.id === LIB.parent_id; });
        const cr = document.querySelector(".crumbs");
        if (cr && parent) cr.innerHTML = '<a href="index.html">← All libraries</a> &nbsp;·&nbsp; ' +
          '<a href="library.html?id=' + esc(parent.id) + '">' + esc(parent.name) + '</a>';
      }
      document.getElementById("lib-name").innerHTML = esc(LIB.name) +
        (LIB.parent_id ? ' <span class="badge flat">' + esc((ALLLIBS.find(function (l) { return l.id === LIB.parent_id; }) || {}).name || "") + ' component</span>' : '') +
        ' <span class="badge flat">since ' + esc(LIB.released_on) + '</span>';
      // Subhead = description only; the counts sit beside the "Adoption over time" title.
      document.getElementById("lib-meta").innerHTML = esc(LIB.description || "");
      // Flagged CPU-backend libs (NVPL) headline confirmed + Backend, with the
      // composition broken out; all other libs stay confirmed-only.
      const bandCount = function (classification, count, label) {
        return coverage[classification] === "not_evaluated"
          ? ('<b>—</b> ' + label + ' <span class="muted">(not evaluated)</span>')
          : ('<b>' + (count || 0) + '</b> ' + label);
      };
      document.getElementById("lib-counts").innerHTML = LIB.adoption_counts_build
        ? ('<b>' + (LIB.headline_count || 0) + '</b> integrations' +
           ' <span class="sep">·</span> ' + bandCount("confirmed", LIB.confirmed_count, "#include") +
           ' <span class="sep">·</span> ' + bandCount("bundled", LIB.bundled_count, MIDLABEL.toLowerCase()) +
           ' <span class="sep">·</span> ' + bandCount("targeted", LIB.targeted_count, "targeted"))
        : (bandCount("confirmed", LIB.confirmed_count, "integrations") +
           ' <span class="sep">·</span> ' + bandCount("bundled", LIB.bundled_count, MIDLABEL.toLowerCase()) +
           ' <span class="sep">·</span> ' + bandCount("targeted", LIB.targeted_count, "targeted"));
      document.getElementById("caveats").innerHTML =
        "<h3>Method &amp; caveats</h3>" +
        (function () {
          const discovery = (handle.index && handle.index.discovery_coverage) ||
            LIB.discovery_coverage || {};
          const sources = Object.keys(discovery.sources || {}).sort();
          const sourceText = sources.length
            ? sources.map(function (source) {
                const state = discovery.sources[source] || {};
                return source + ": " +
                  (state.complete === true ? "complete" : "not complete") +
                  (state.as_of ? " as of " + String(state.as_of).slice(0, 10) : "") +
                  (state.stale ? " (stale)" : "");
              }).join(" · ")
            : "source coverage not evaluated for this migrated snapshot";
          return '<p class="muted"><b>Discovery coverage:</b> ' +
            esc(sourceText) +
            (discovery.gap_count ? " · " + discovery.gap_count + " gap(s)" : "") +
            "</p>";
        })() +
        "<ul>" + (cur.caveats || []).map(function (c) {
          return "<li>" + esc(c) + "</li>"; }).join("") + "</ul>";
      takeaways(); chart(); renderComponents(); headers(); rows();
      updateRepoParts();
      // Research citations view (REQ-07)
      citHeader(); citPapers(); citHeaders(); citCaveats(); setupTabs();
      // Warm the bounded citation summary immediately so the Research usage
      // velocity cards are ready without requiring the tab to be opened.
      // The chart itself still waits for the visible tab so it can size safely.
      ensureCitations().catch(function () {
        /* ensureCitations renders a retryable page-level status */
      });
      // deep-link: library.html?id=…#citations opens the citations view directly
      if ((location.hash || "").indexOf("citations") >= 0) {
        const cb = document.querySelector('.tab-btn[data-view="citations"]');
        if (cb) cb.click();
      }
      ["cit-search", "cit-filter"].forEach(function (i) {
        const rerenderCitations = async function () {
          try {
            await ensureAllCitations();
            visibleCitationLimit = 200;
            citPapers();
          } catch (_error) {
            // The page-level status remains retryable.
          }
        };
        document.getElementById(i).addEventListener("input", rerenderCitations);
        document.getElementById(i).addEventListener("change", rerenderCitations);
      });
      document.getElementById("cit-dl-csv").addEventListener("click", function (ev) {
        ev.preventDefault(); openCitDialog("csv").catch(function () {});
      });
      document.getElementById("cit-dl-json").addEventListener("click", function (ev) {
        ev.preventDefault(); openCitDialog("json").catch(function () {});
      });
      document.getElementById("cit-dl-cancel").addEventListener("click", function (ev) { ev.preventDefault(); closeCitDialog(); });
      document.getElementById("cit-dl-go").addEventListener("click", function (ev) { ev.preventDefault(); doCitDownload(); });
      document.getElementById("cit-dl-modal").addEventListener("click", function (ev) { if (ev.target.id === "cit-dl-modal") closeCitDialog(); });

      // operator expand/collapse (delegated; tbody persists across re-renders)
      document.querySelector("#repos tbody").addEventListener("click", function (ev) {
        const t = ev.target.closest(".ops-toggle");
        if (!t) return;
        ev.preventDefault();
        const fn = t.dataset.fn;
        expandedOps[fn] = !expandedOps[fn];
        rows();
      });

      ["search", "klass"].forEach(function (i) {
        const rerender = async function () {
          // Filtering is a deliberate request for global library membership,
          // so load the remaining shards before claiming "no match".
          if (HANDLE) {
            await CXITData.loadAllRepositoryParts(HANDLE);
            REPOS = HANDLE.repos;
          }
          visibleRepoLimit = 200;
          rows(); updateRepoParts();
        };
        document.getElementById(i).addEventListener("input", rerender);
        document.getElementById(i).addEventListener("change", rerender);
      });

      // download dialog
      document.getElementById("dl-csv").addEventListener("click", function (ev) { ev.preventDefault(); openDialog("csv"); });
      document.getElementById("dl-json").addEventListener("click", function (ev) { ev.preventDefault(); openDialog("json"); });
      document.getElementById("dl-cancel").addEventListener("click", function (ev) { ev.preventDefault(); closeDialog(); });
      document.getElementById("dl-go").addEventListener("click", function (ev) { ev.preventDefault(); doDownload(); });
      document.getElementById("dl-modal").addEventListener("click", function (ev) { if (ev.target.id === "dl-modal") closeDialog(); });
      document.getElementById("repo-more").addEventListener("click", function () {
        const button = this;
        button.disabled = true;
        const filtered = currentList().length;
        const operation = visibleRepoLimit < filtered
          ? Promise.resolve([])
          : CXITData.loadNextRepositoryPart(HANDLE);
        operation.then(function () {
          visibleRepoLimit += 200;
          REPOS = HANDLE.repos; rows(); updateRepoParts();
        }).catch(function (error) {
          document.getElementById("repo-part-status").textContent =
            "Could not load more repositories: " + error.message;
        }).finally(function () { button.disabled = false; });
      });
    })
    .catch(function (e) {
      document.getElementById("lib-name").textContent = "Could not load data";
      document.getElementById("lib-meta").textContent = e.message;
    });
})();

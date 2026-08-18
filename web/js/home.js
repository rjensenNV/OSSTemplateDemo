// Homescreen: library cards with filter / sort / search + rolling 7-day activity.
(function () {
  let DATA = null, CITMAP = {}, EXPORTS = null;
  // CITMAP: lib id -> total research mentions

  function renderMeta(d) {
    document.getElementById("meta").innerHTML =
      "Last refreshed <b>" + fmtDate(d.generated_at) + "</b>" +
      ' &nbsp;·&nbsp; <span class="muted">refreshes weekly</span>';
  }

  // Four labels distributed across the monthly observations and positioned on
  // the same real-time scale as the sparkline. The current partial month shows
  // its actual collection day (for example 8/3/26).
  function monthTicks(months, n, asOf) {
    if (!months || !months.length) return [];
    n = Math.min(n, months.length);
    const timeline = monthlyTimeline(months, asOf);
    if (timeline.length !== months.length) return [];
    const first = timeline[0].timestamp;
    const span = (timeline[timeline.length - 1].timestamp - first) || 1;
    const out = [];
    for (let i = 0; i < n; i++) {
      const idx = n === 1 ? 0 : Math.round(i * (months.length - 1) / (n - 1));
      const point = timeline[idx];
      const label = point.partial
        ? parseInt(point.date.slice(5, 7), 10) + "/" +
          parseInt(point.date.slice(8, 10), 10) + "/" + point.date.slice(2, 4)
        : parseInt(point.month.slice(5, 7), 10) + "/" + point.month.slice(2, 4);
      out.push({
        label: label,
        left: ((point.timestamp - first) / span * 100).toFixed(2)
      });
    }
    return out;
  }

  function cardHTML(lib) {
    const c = CITMAP[lib.id] || {};
    const repoNew = (lib.new_repos_7d || 0) > 0 ? lib.new_repos_7d : 0;
    const paperNew = (c.newCount || 0) > 0 ? c.newCount : 0;
    const hasNew = repoNew > 0 || paperNew > 0;
    const mid = lib.bundled_label ? lib.bundled_label.toLowerCase()
              : (lib.language === "python") ? "declared" : "bundled";
    // Headline = confirmed, or confirmed+Backend for flagged libs (NVPL). When summed,
    // the sub-line breaks it out as "{confirmed} #include · {bundled} backend".
    const big = (lib.headline_count != null)
      ? lib.headline_count
      : (lib.confirmed_count != null ? lib.confirmed_count : null);
    const coverage = lib.classification_coverage || {};
    const band = function (name, count, label) {
      return coverage[name] === "not_evaluated"
        ? label + " not evaluated"
        : (count || 0) + " " + label;
    };
    const details = [];
    if (lib.adoption_counts_build) {
      details.push(band("confirmed", lib.confirmed_count, "#include"));
    }
    if (coverage.bundled !== "not_evaluated") {
      details.push(band("bundled", lib.bundled_count, mid));
    }
    details.push(band("targeted", lib.targeted_count, "targeted"));
    if (c.total != null) details.push(c.total + " papers");
    const asOf = lib.timeseries_as_of || DATA.generated_at;
    const ticks = monthTicks(lib.sparkline_months, 4, asOf);
    let badges = "";
    if (repoNew) badges += '<span class="badge up">▲ ' + repoNew + " repo" + (repoNew === 1 ? "" : "s") + "</span> ";
    if (paperNew) badges += '<span class="badge up">▲ ' + paperNew + " paper" + (paperNew === 1 ? "" : "s") + "</span>";
    return '' +
      '<div class="card' + (hasNew ? " has-new" : "") + '" data-id="' + lib.id + '">' +
        '<div class="row"><span class="name">' + esc(lib.name) + '</span>' +
          '<span class="badge flat">since ' + esc(lib.released_on) + '</span></div>' +
        '<div class="desc">' + esc(lib.description || "") + '</div>' +
        '<div class="big">' +
          (big == null
            ? (
              lib.collection_status === "not_collected"
                ? 'Not collected<small>deferred from this partial release</small>'
                : 'Metric pending<small>not evaluated</small>'
            )
            : big + '<small>integrations</small>') +
        '</div>' +
        '<div class="muted" style="font-size:12px;margin:-2px 0 4px">' +
          details.join(' · ') + '</div>' +
        '<div class="card-badges">' + badges + '</div>' +
        sparkline(lib.sparkline, 240, 50, null, lib.sparkline_months, asOf) +
        '<div class="spark-axis muted">' + ticks.map(function (t) {
          return '<span style="left:' + t.left + '%">' + esc(t.label) + "</span>";
        }).join("") + '</div>' +
        (lib.scan_capped ? '<div class="stat" style="margin-top:8px"><span class="badge warn">scan capped: ' + esc(lib.scan_capped) + '</span></div>' : '') +
      '</div>';
  }

  function render() {
    const q = document.getElementById("search").value.toLowerCase().trim();
    const sort = document.getElementById("sort").value;
    const onlyNew = document.getElementById("onlynew").checked;
    // Every independently collected component is a first-class landing card.
    // NVPL alone is additive, so its projected child breakdown stays on the
    // consolidated NVPL page instead of duplicating the family on home.
    let libs = DATA.libraries.filter(function (l) {
      return l.collection_status === "collected"
        && l.metric_contract_status !== "pending"
        && (!l.is_component || l.parent_id !== "nvpl");
    });
    if (q) libs = libs.filter(function (l) {
      return (l.name + " " + (l.description || "")).toLowerCase().indexOf(q) >= 0; });
    const newActivity = function (l) {
      const citation = CITMAP[l.id] || {};
      return (l.new_repos_7d || 0) + (citation.newCount || 0);
    };
    if (onlyNew) libs = libs.filter(function (l) { return newActivity(l) > 0; });

    // Rank by the headline adoption metric (REQ-05: confirmed; for flagged CPU-backend
    // libs like NVPL, confirmed + Backend per `headline_count`).
    const tot = function (l) {
      return l.headline_count != null
        ? l.headline_count
        : (l.confirmed_count != null ? l.confirmed_count : null);
    };
    const adoptionSort = function (direction) {
      return function (a, b) {
        const av = tot(a), bv = tot(b);
        if (av == null && bv == null) return a.name.localeCompare(b.name);
        if (av == null) return 1;
        if (bv == null) return -1;
        return direction * (av - bv);
      };
    };
    const cmp = {
      adopters_desc: adoptionSort(-1),
      adopters_asc: adoptionSort(1),
      alpha: function (a, b) { return a.name.localeCompare(b.name); },
      delta_desc: function (a, b) { return newActivity(b) - newActivity(a); },
      trending_desc: function (a, b) { return (b.trending_90d || 0) - (a.trending_90d || 0); }
    }[sort];
    libs.sort(cmp);

    const grid = document.getElementById("grid");
    grid.innerHTML = libs.length
      ? libs.map(function (l) { return cardHTML(l); }).join("")
      : '<div class="empty">No libraries match.</div>';
    Array.prototype.forEach.call(grid.querySelectorAll(".card"), function (c) {
      c.addEventListener("click", function () { location.href = "library.html?id=" + c.dataset.id; });
    });
  }

  function renderCaveats(d) {
    document.getElementById("caveats").innerHTML =
      "<h3>Method &amp; caveats</h3><ul>" +
      (d.caveats || []).map(function (c) { return "<li>" + esc(c) + "</li>"; }).join("") + "</ul>";
  }

  async function showExports() {
    const root = document.getElementById("export-links");
    const button = document.getElementById("show-exports");
    if (!EXPORTS) {
      root.hidden = false;
      root.textContent = "Repository exports are available after the V2 cutover.";
      return;
    }
    button.disabled = true;
    root.hidden = false;
    root.textContent = "Loading export index…";
    try {
      const exports = await CXITData.loadExportIndex(EXPORTS);
      const links = [];
      [["JSONL", exports.jsonl], ["CSV", exports.csv]].forEach(function (group) {
        group[1].forEach(function (part, ordinal) {
          links.push(
            '<a class="dl-btn" href="' + esc(part.url) + '" download>' +
            esc(group[0]) + " part " + (ordinal + 1) + "</a>"
          );
        });
      });
      const streamButtons = window.showSaveFilePicker
        ? '<button type="button" class="full-export" data-format="jsonl">Download complete JSONL</button> ' +
          '<button type="button" class="full-export" data-format="csv">Download complete CSV</button> '
        : "";
      root.innerHTML = streamButtons +
        "Content-addressed export parts: " + links.join(" ");
      Array.prototype.forEach.call(
        root.querySelectorAll(".full-export"),
        function (download) {
          download.addEventListener("click", async function () {
            const format = download.dataset.format;
            const parts = format === "csv" ? exports.csv : exports.jsonl;
            download.disabled = true;
            download.textContent = "Streaming " + format.toUpperCase() + "…";
            try {
              await CXITData.streamExportParts(
                parts,
                "cuda-x-repositories." + format,
                format === "csv" ? "text/csv" : "application/x-ndjson"
              );
              download.textContent = "Downloaded " + format.toUpperCase();
            } catch (error) {
              download.textContent = "Retry complete " + format.toUpperCase();
              download.disabled = false;
              root.setAttribute("data-export-error", error.message);
            }
          });
        }
      );
    } catch (error) {
      root.textContent = "Could not load repository exports (" + error.message + ").";
      button.disabled = false;
    }
  }

  CXITData.loadHome().then(function (result) {
    DATA = result.current;
    CITMAP = result.citationMap || {};
    EXPORTS = result.exportsDescriptor || null;
    const d = DATA;
    renderMeta(d); render();
    ["search", "sort", "onlynew"].forEach(function (id) {
      document.getElementById(id).addEventListener("input", render);
      document.getElementById(id).addEventListener("change", render);
    });
    document.getElementById("show-exports").addEventListener("click", showExports);
  }).catch(function (e) {
    document.getElementById("grid").innerHTML =
      '<div class="empty">Could not load validated V2 data (' + esc(e.message) +
      ').<br>The last-good manifest must be restored before this dashboard can load.</div>';
  });
})();

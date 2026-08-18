"use strict";

const assert = require("assert");
const fs = require("fs");
const vm = require("vm");

const commonSource = fs.readFileSync("web/js/common.js", "utf8");
const loaderSource = fs.readFileSync("web/js/data-v2.js", "utf8");
const librarySource = fs.readFileSync("web/js/library.js", "utf8");
const libraryHtml = fs.readFileSync("web/library.html", "utf8");
const homeSource = fs.readFileSync("web/js/home.js", "utf8");
const homeHtml = fs.readFileSync("web/index.html", "utf8");
const styleSource = fs.readFileSync("web/css/style.css", "utf8");

global.window = global;
vm.runInThisContext(commonSource, { filename: "web/js/common.js" });
global.fetch = async function () {
  throw new Error("manifest fetch is not part of this fixture");
};

const calls = [];
let failFirst = false;
let responses = null;
const failures = {};

function partialMonthChartsUseElapsedTime() {
  const timeline = monthlyTimeline(
    ["2026-06", "2026-07", "2026-08"],
    "2026-08-03T03:26:11Z"
  );
  assert.strictEqual(timeline[0].date, "2026-06-30");
  assert.strictEqual(timeline[1].date, "2026-07-31");
  assert.strictEqual(timeline[2].date, "2026-08-03");
  assert.strictEqual(timeline[2].partial, true);
  assert.strictEqual(
    (timeline[2].timestamp - timeline[1].timestamp) / 86400000,
    3,
    "the current month must end on the collection date, not month-end"
  );
  assert.strictEqual(
    timelineTooltipLabel(timeline[2].timestamp, timeline),
    "2026-08-03 (partial month)"
  );

  const svg = sparkline(
    [10, 20, 20], 240, 50, null,
    ["2026-06", "2026-07", "2026-08"],
    "2026-08-03T03:26:11Z"
  );
  const points = svg.match(/points="([^"]+)"/)[1].split(" ");
  const julyX = +points[1].split(",")[0];
  const augustX = +points[2].split(",")[0];
  assert.ok(
    augustX - julyX < 30,
    "the partial-month sparkline segment must be much shorter than a full month"
  );
}
global.loadJSON = async function (path) {
  calls.push(path);
  // Deliberately keep the request pending for a turn so concurrent callers
  // overlap deterministically.
  await new Promise(function (resolve) { setImmediate(resolve); });
  if (failFirst) {
    failFirst = false;
    throw new Error("fixture failure");
  }
  if (failures[path]) {
    failures[path] -= 1;
    throw new Error("fixture failure for " + path);
  }
  if (responses && Object.prototype.hasOwnProperty.call(responses, path)) {
    return JSON.parse(JSON.stringify(responses[path]));
  }
  return { rows: [{ full_name: path }] };
};

vm.runInThisContext(loaderSource, { filename: "web/js/data-v2.js" });

async function concurrentRepositoryLoadsAreSingleFlight() {
  const handle = {
    mode: "v2",
    repos: [],
    repoParts: [
      { path: "libraries/x/repos/part-000.json" },
      { path: "libraries/x/repos/part-001.json" },
      { path: "libraries/x/repos/part-002.json" }
    ],
    nextRepoPart: 0,
    repositoryPartLoading: null
  };
  await Promise.all([
    CXITData.loadAllRepositoryParts(handle),
    CXITData.loadAllRepositoryParts(handle),
    CXITData.loadAllRepositoryParts(handle)
  ]);
  assert.deepStrictEqual(calls, [
    "data/v2/libraries/x/repos/part-000.json",
    "data/v2/libraries/x/repos/part-001.json",
    "data/v2/libraries/x/repos/part-002.json"
  ]);
  assert.strictEqual(handle.nextRepoPart, 3);
  assert.strictEqual(handle.repos.length, 3);
  assert.deepStrictEqual(
    handle.repos.map(function (row) { return row.full_name; }),
    calls
  );
}

async function failedShardCanBeRetriedWithoutCursorLoss() {
  calls.length = 0;
  failFirst = true;
  const handle = {
    mode: "v2",
    repos: [],
    repoParts: [{ path: "libraries/x/repos/part-000.json" }],
    nextRepoPart: 0,
    repositoryPartLoading: null
  };
  await assert.rejects(
    CXITData.loadNextRepositoryPart(handle),
    /fixture failure/
  );
  assert.strictEqual(handle.nextRepoPart, 0);
  assert.strictEqual(handle.repos.length, 0);
  await CXITData.loadNextRepositoryPart(handle);
  assert.strictEqual(handle.nextRepoPart, 1);
  assert.strictEqual(handle.repos.length, 1);
  assert.strictEqual(calls.length, 2);
}

function citationHandle() {
  return {
    mode: "v2",
    library: { id: "x" },
    manifest: { quality: { path: "quality.json" } },
    citationDescriptor: { path: "citations/x/index.json" },
    citationsLoaded: false,
    citationLoading: null,
    citationParts: [],
    nextCitationPart: 0,
    citationPartLoading: null
  };
}

function citationResponses() {
  return {
    "data/v2/quality.json": {
      citation: { caveats: ["fixture"] }
    },
    "data/v2/citations/x/index.json": {
      library_id: "x",
      row_count: 2,
      repo_papers: {},
      paper_parts: [
        { path: "citations/x/part-000.json" },
        { path: "citations/x/part-001.json" }
      ]
    },
    "data/v2/citations/x/part-000.json": {
      rows: [{ title: "first", repo: "public/one" }]
    },
    "data/v2/citations/x/part-001.json": {
      rows: [{ title: "second", repo: "public/two" }]
    }
  };
}

async function citationsLoadOnePageAndContinueSingleFlight() {
  calls.length = 0;
  responses = citationResponses();
  const handle = citationHandle();
  const results = await Promise.all([
    CXITData.loadCitations(handle),
    CXITData.loadCitations(handle)
  ]);
  assert.strictEqual(results[0], results[1]);
  assert.deepStrictEqual(calls, [
    "data/v2/quality.json",
    "data/v2/citations/x/index.json",
    "data/v2/citations/x/part-000.json"
  ]);
  assert.strictEqual(handle.citationsLoaded, true);
  assert.strictEqual(handle.nextCitationPart, 1);
  assert.deepStrictEqual(
    results[0].citation.papers.map(function (paper) { return paper.title; }),
    ["first"]
  );

  await Promise.all([
    CXITData.loadNextCitationPart(handle),
    CXITData.loadNextCitationPart(handle)
  ]);
  assert.strictEqual(
    calls.filter(function (path) {
      return path === "data/v2/citations/x/part-001.json";
    }).length,
    1
  );
  assert.strictEqual(handle.nextCitationPart, 2);
  assert.deepStrictEqual(
    handle.citationResult.citation.papers.map(function (paper) {
      return paper.title;
    }),
    ["first", "second"]
  );
  assert.deepStrictEqual(
    Object.keys(handle.citationResult.citation.repo_papers).sort(),
    ["public/one", "public/two"]
  );
}

async function failedCitationLoadCanRetryCleanly() {
  calls.length = 0;
  responses = citationResponses();
  const indexPath = "data/v2/citations/x/index.json";
  failures[indexPath] = 1;
  const handle = citationHandle();
  await assert.rejects(CXITData.loadCitations(handle), /fixture failure/);
  assert.strictEqual(handle.citationsLoaded, false);
  assert.strictEqual(handle.citationLoading, null);
  assert.strictEqual(handle.nextCitationPart, 0);

  const result = await CXITData.loadCitations(handle);
  assert.strictEqual(result.citation.papers.length, 1);
  assert.strictEqual(handle.citationsLoaded, true);
  assert.strictEqual(
    calls.filter(function (path) { return path === indexPath; }).length,
    2
  );
}

async function completeCsvDownloadHasExactlyOneHeader() {
  const originalFetch = global.fetch;
  const originalPicker = global.showSaveFilePicker;
  const encoder = new TextEncoder();
  const chunksByPath = {
    "part-0.csv": [encoder.encode("name,value\nfirst,1\n")],
    "part-1.csv": [
      encoder.encode("name,"),
      encoder.encode("value\nsecond,2\n")
    ],
    "part-2.csv": null
  };
  const written = [];
  let closed = false;
  global.showSaveFilePicker = async function () {
    return {
      createWritable: async function () {
        return {
          write: async function (value) {
            written.push(Buffer.from(value));
          },
          close: async function () { closed = true; },
          abort: async function () { throw new Error("unexpected abort"); }
        };
      }
    };
  };
  global.fetch = async function (path) {
    const chunks = chunksByPath[path];
    if (chunks === null) {
      return {
        ok: true,
        body: null,
        arrayBuffer: async function () {
          return encoder.encode("name,value\nthird,3\n").buffer;
        }
      };
    }
    let offset = 0;
    return {
      ok: true,
      body: {
        getReader: function () {
          return {
            read: async function () {
              if (offset >= chunks.length) return { done: true };
              return { done: false, value: chunks[offset++] };
            }
          };
        }
      }
    };
  };
  try {
    await CXITData.streamExportParts(
      [
        { url: "part-0.csv", descriptor: { path: "part-0.csv" } },
        { url: "part-1.csv", descriptor: { path: "part-1.csv" } },
        { url: "part-2.csv", descriptor: { path: "part-2.csv" } }
      ],
      "repositories.csv",
      "text/csv"
    );
  } finally {
    global.fetch = originalFetch;
    global.showSaveFilePicker = originalPicker;
  }
  assert.strictEqual(closed, true);
  assert.strictEqual(
    Buffer.concat(written).toString("utf8"),
    "name,value\nfirst,1\nsecond,2\nthird,3\n"
  );
}

function libraryContractsAreExplicit() {
  assert.doesNotMatch(
    commonSource,
    /<circle/,
    "sparklines must not draw a clipped endpoint marker"
  );
  assert.match(
    librarySource,
    /xAxis: \{ type: "time"/,
    "repository and paper charts must use real date axes"
  );
  assert.match(
    librarySource,
    /TS && TS\.as_of/,
    "repository charts must use the published collection timestamp"
  );
  assert.match(
    librarySource,
    /CIT\.as_of \|\| \(CIT\.coverage \|\| \{\}\)\.as_of/,
    "paper charts must use citation collection time"
  );
  assert.match(
    homeSource,
    /sparkline\(lib\.sparkline, 240, 50, null, lib\.sparkline_months, asOf\)/,
    "landing sparklines must use the release collection time"
  );
  assert.match(
    homeSource,
    /l\.collection_status === "collected"[\s\S]*l\.metric_contract_status !== "pending"[\s\S]*!l\.is_component \|\| l\.parent_id !== "nvpl"/,
    "home must show collected libraries and components while hiding pending cards"
  );
  assert.match(
    librarySource,
    /CONFLABEL = LIB\.adoption_counts_build \? "Direct #include" : "Integration"/,
    "NVPL charts must distinguish direct includes from Backend integration"
  );
  assert.match(
    libraryHtml,
    /Components\s*<span[^>]*>— adoption by component<\/span>/,
    "component sections must use concise, accurate adoption wording"
  );
  assert.match(
    libraryHtml,
    /data-k="publication_date" class="num">Published</,
    "paper table must expose the full publication date"
  );
  assert.match(
    librarySource,
    /p\.publication_date \? fmtDate\(p\.publication_date\) : \(p\.year \|\| "—"\)/,
    "paper rows must render a full date while retaining a year-only fallback"
  );
  assert.match(
    librarySource,
    /citSortKey === "publication_date"[\s\S]*String\(a\.year\) \+ "-01-01"/,
    "publication-date sorting must remain deterministic for legacy year-only rows"
  );
  assert.match(
    librarySource,
    /Metric pending<small>not evaluated<\/small>/,
    "pending component metrics must not render a numeric zero"
  );
  assert.match(
    librarySource,
    /takeaways\(\); citHeader\(\);/,
    "citation loading must refresh research takeaways"
  );
  assert.match(
    librarySource,
    /citCaveats\(\); setupTabs\(\);[\s\S]*ensureCitations\(\)\.catch/,
    "library initialization must warm research velocity before the tab is opened"
  );
  assert.doesNotMatch(
    librarySource,
    /CIT\.errors \|\||coverage\.errors \|\|/,
    "raw collector failures must never render in the public Research Usage header"
  );
  assert.match(
    librarySource,
    /async function jumpToRepo\(repo\)[\s\S]*await CXITData\.loadAllRepositoryParts\(HANDLE\)/,
    "paper-to-repository jumps must search every repository shard"
  );
  assert.match(
    librarySource,
    /Load next research page/,
    "citation shards must expose an explicit bounded paging affordance"
  );
  assert.match(
    librarySource,
    /CIT_LOADING === loading\) CIT_LOADING = null/,
    "a failed citation UI load must leave the tab retryable"
  );
  assert.match(
    librarySource,
    /id="cit-retry">Retry/,
    "a failed citation load must expose a direct retry action"
  );
  assert.match(
    librarySource,
    /<b>Discovery coverage:<\/b>/,
    "library detail must render source-specific discovery freshness"
  );
  assert.match(
    librarySource,
    /" of " \+ filtered \+ " matching repositories"/,
    "a filtered repository status must use the filtered result count as its denominator"
  );
  assert.match(
    librarySource,
    /" of " \+ total \+ " repositories"/,
    "an unfiltered repository status must retain the library-wide total"
  );
}

function exportContractIsLazyAndDirect() {
  assert.match(
    loaderSource,
    /portfolio_coverage: m\.portfolio_coverage \|\| null/,
    "home data must retain explicit partial-portfolio coverage metadata"
  );
  assert.doesNotMatch(
    homeSource,
    /release\.scope === "partial-portfolio"|collected,.*deferred/,
    "the dashboard subhead must not expose internal cohort/deferred wording"
  );
  assert.match(
    homeSource,
    /Not collected<small>deferred from this partial release<\/small>/,
    "deferred cards must not render as measured zeros or pending contracts"
  );
  assert.match(
    loaderSource,
    /newCount: library\.citation_new_7d \|\| 0/,
    "homepage paper badges must use the rolling seven-day count"
  );
  assert.match(
    homeSource,
    /lib\.new_repos_7d/,
    "homepage repository badges must use the rolling seven-day count"
  );
  assert.doesNotMatch(
    homeSource,
    /last 7d/,
    "weekly activity badges must not repeat the implied seven-day window"
  );
  assert.match(
    homeSource,
    /coverage\.bundled !== "not_evaluated"/,
    "homepage cards must omit bundled when that band was not evaluated"
  );
  assert.doesNotMatch(
    homeSource,
    /lib\.delta_since_last/,
    "homepage activity controls must not use an arbitrary prior-refresh interval"
  );
  assert.match(
    loaderSource,
    /async function loadExportIndex\(descriptor\)/,
    "the full export index must remain lazy"
  );
  assert.match(
    homeSource,
    /href="' \+ esc\(part\.url\) \+ '" download/,
    "export parts must remain available as direct downloads"
  );
  assert.match(
    loaderSource,
    /response\.body\.getReader\(\)/,
    "a complete export must stream each response body"
  );
  assert.match(
    loaderSource,
    /await handle\.createWritable\(\)/,
    "a complete export must write to a browser file stream"
  );
  assert.doesNotMatch(
    loaderSource,
    /Promise\.all\(parts\.map/,
    "a complete export must not buffer all shards concurrently"
  );
  const csv = toCSV(
    ["description", "ordinary"],
    [{ description: " \t=HYPERLINK(\"bad\")", ordinary: "safe" }]
  );
  assert.match(
    csv,
    /^description,ordinary\n"' \t=HYPERLINK\(""bad""\)",safe$/,
    "client-side CSV must neutralize formula-leading repository text"
  );
}

function coverageNoticeIsOneTimeAndDismissible() {
  assert.match(
    commonSource,
    /cdi:data-coverage-notice:2026-08-10:v1/,
    "the coverage notice must have a versioned browser-persistence key"
  );
  assert.match(
    commonSource,
    /localStorage/,
    "the coverage notice must persist across visits in the browser profile"
  );
  assert.match(
    commonSource,
    /Close data coverage notice/,
    "the coverage notice must provide an accessible close button"
  );
  assert.match(
    commonSource,
    /August 3, 2026/,
    "the coverage notice must identify the dashboard snapshot date"
  );
  assert.match(styleSource, /\.coverage-notice-close:focus-visible/);
  assert.match(homeHtml, /common\.js\?v=20260810a/);
  assert.match(libraryHtml, /common\.js\?v=20260810a/);
}

(async function main() {
  partialMonthChartsUseElapsedTime();
  await concurrentRepositoryLoadsAreSingleFlight();
  await failedShardCanBeRetriedWithoutCursorLoss();
  await citationsLoadOnePageAndContinueSingleFlight();
  await failedCitationLoadCanRetryCleanly();
  await completeCsvDownloadHasExactlyOneHeader();
  libraryContractsAreExplicit();
  exportContractIsLazyAndDirect();
  coverageNoticeIsOneTimeAndDismissible();
  process.stdout.write("REQ-14 frontend tests passed\n");
})().catch(function (error) {
  console.error(error);
  process.exitCode = 1;
});

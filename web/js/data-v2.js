// Manifest-driven V2 data access. The last V1 release is retained in Git only
// for an explicit reviewed rollback; production never silently falls back.
//
// Home never requests repository or citation artifacts. Library detail loads
// one adoption shard initially; remaining adoption shards are explicit. Paper
// shards are not requested until the Research usage tab is opened.
(function (global) {
  "use strict";

  let manifestPromise = null;

  async function manifest() {
    if (!manifestPromise) {
      manifestPromise = loadJSON("data/v2/manifest.json").then(function (value) {
        if (!value || value.schema_version !== "2.0") {
          throw new Error("unsupported CUDA-X data schema " + value.schema_version);
        }
        return value;
      });
    }
    return manifestPromise;
  }

  function artifactPath(descriptor) {
    if (!descriptor || !descriptor.path || /(^|\/)\.\.(\/|$)/.test(descriptor.path)) {
      throw new Error("invalid V2 artifact descriptor");
    }
    return "data/v2/" + descriptor.path;
  }

  function homeCurrent(m) {
    return {
      generated_at: m.generated_at || (m.release && m.release.generated_at),
      totals: m.totals || {},
      caveats: m.caveats || [],
      libraries: m.libraries || [],
      is_bootstrap: !!(m.release && m.release.is_bootstrap),
      release: m.release || {},
      portfolio_coverage: m.portfolio_coverage || null
    };
  }

  async function loadHome() {
    const m = await manifest();
    const citationMap = {};
    (m.libraries || []).forEach(function (library) {
      if (library.citation_total != null) {
        citationMap[library.id] = {
          total: library.citation_total,
          newCount: library.citation_new_7d || 0
        };
      }
    });
    return {
      mode: "v2",
      current: homeCurrent(m),
      citationMap: citationMap,
      exportsDescriptor: m.exports || null
    };
  }

  async function loadExportIndex(descriptor) {
    if (!descriptor) return null;
    const index = await loadJSON(artifactPath(descriptor));
    return {
      index: index,
      jsonl: (index.jsonl_parts || []).map(function (part) {
        return { descriptor: part, url: artifactPath(part) };
      }),
      csv: (index.csv_parts || []).map(function (part) {
        return { descriptor: part, url: artifactPath(part) };
      })
    };
  }

  async function streamExportParts(parts, suggestedName, mimeType) {
    if (!global.showSaveFilePicker) {
      throw new Error("streamed downloads are not supported by this browser");
    }
    const handle = await global.showSaveFilePicker({
      suggestedName: suggestedName,
      types: [{
        description: "CUDA-X repository export",
        accept: (function () {
          const value = {};
          value[mimeType] = [
            suggestedName.slice(suggestedName.lastIndexOf("."))
          ];
          return value;
        })()
      }]
    });
    const writable = await handle.createWritable();
    try {
      for (let ordinal = 0; ordinal < parts.length; ordinal += 1) {
        const part = parts[ordinal];
        const response = await fetch(part.url, { cache: "no-store" });
        if (!response.ok) {
          throw new Error(
            "failed to stream " + part.descriptor.path + ": " + response.status
          );
        }
        if (response.body && response.body.getReader) {
          const reader = response.body.getReader();
          let strippingHeader = mimeType === "text/csv" && ordinal > 0;
          while (true) {
            const item = await reader.read();
            if (item.done) break;
            let chunk = item.value;
            if (strippingHeader) {
              const newline = chunk.indexOf(10);
              if (newline < 0) continue;
              strippingHeader = false;
              chunk = chunk.slice(newline + 1);
            }
            if (chunk.length) await writable.write(chunk);
          }
          if (strippingHeader) {
            throw new Error("CSV export part is missing its header terminator");
          }
        } else {
          // Compatibility fallback is bounded to one artifact, never the
          // complete multi-part export.
          let chunk = new Uint8Array(await response.arrayBuffer());
          if (mimeType === "text/csv" && ordinal > 0) {
            const newline = chunk.indexOf(10);
            if (newline < 0) {
              throw new Error("CSV export part is missing its header terminator");
            }
            chunk = chunk.slice(newline + 1);
          }
          if (chunk.length) await writable.write(chunk);
        }
      }
      await writable.close();
    } catch (error) {
      await writable.abort();
      throw error;
    }
  }

  async function loadLibrary(id) {
    const m = await manifest();
    const library = (m.libraries || []).find(function (candidate) {
      return candidate.id === id;
    });
    if (!library) {
      return {
        mode: "v2", current: homeCurrent(m), manifest: m, library: null,
        libraries: m.libraries || [], timeseries: {}, repos: [], repoParts: [],
        nextRepoPart: 0, repositoryPartLoading: null,
        citationDescriptor: null, citationsLoaded: false, citationLoading: null,
        citationParts: [], nextCitationPart: 0, citationPartLoading: null
      };
    }
    const index = await loadJSON(artifactPath(library.index));
    const parts = index.repo_parts || [];
    let repos = [];
    let next = 0;
    if (parts.length) {
      const shard = await loadJSON(artifactPath(parts[0]));
      repos = shard.rows || [];
      next = 1;
    }
    return {
      mode: "v2",
      current: homeCurrent(m),
      manifest: m,
      library: library,
      libraries: m.libraries || [],
      index: index,
      timeseries: index.timeseries || {},
      repos: repos,
      repoParts: parts,
      nextRepoPart: next,
      repositoryPartLoading: null,
      citationDescriptor: library.citations_index,
      citationsLoaded: false,
      citationLoading: null,
      citationParts: [],
      nextCitationPart: 0,
      citationPartLoading: null
    };
  }

  async function loadNextRepositoryPart(handle) {
    if (handle.mode !== "v2" || handle.nextRepoPart >= handle.repoParts.length) {
      return [];
    }
    // Search, sort, download, and "load more" can ask for shards at the same
    // time. Share one in-flight read so concurrent callers cannot fetch the
    // same ordinal, append it twice, increment twice, and skip its successor.
    if (handle.repositoryPartLoading) {
      return handle.repositoryPartLoading;
    }
    const ordinal = handle.nextRepoPart;
    const descriptor = handle.repoParts[ordinal];
    const loading = loadJSON(artifactPath(descriptor)).then(function (shard) {
      // Only this single-flight request may advance the cursor it captured.
      if (handle.nextRepoPart !== ordinal) {
        throw new Error("repository shard cursor changed during load");
      }
      const rows = shard.rows || [];
      Array.prototype.push.apply(handle.repos, rows);
      handle.nextRepoPart = ordinal + 1;
      return rows;
    }).finally(function () {
      if (handle.repositoryPartLoading === loading) {
        handle.repositoryPartLoading = null;
      }
    });
    handle.repositoryPartLoading = loading;
    return loading;
  }

  async function loadAllRepositoryParts(handle) {
    while (handle.mode === "v2" && handle.nextRepoPart < handle.repoParts.length) {
      await loadNextRepositoryPart(handle);
    }
    return handle.repos;
  }

  async function loadCitations(handle) {
    if (handle.citationsLoaded) return handle.citationResult;
    if (handle.citationLoading) return handle.citationLoading;
    const loading = (async function () {
      let result;
      let parts = [];
      let nextPart = 0;
      let derivedRepoPapers = false;
      if (!handle.citationDescriptor) {
        result = { root: null, citation: null };
      } else {
        const qualityPromise = handle.manifest.quality
          ? loadJSON(artifactPath(handle.manifest.quality)).catch(function () { return null; })
          : Promise.resolve(null);
        const pair = await Promise.all([
          loadJSON(artifactPath(handle.citationDescriptor)),
          qualityPromise
        ]);
        const citation = pair[0];
        const quality = pair[1];
        parts = citation.paper_parts || [];
        citation.papers = [];
        if (parts.length) {
          const first = await loadJSON(artifactPath(parts[0]));
          Array.prototype.push.apply(citation.papers, first.rows || []);
          nextPart = 1;
        }
        citation.repo_papers = citation.repo_papers || {};
        derivedRepoPapers = !Object.keys(citation.repo_papers).length;
        if (derivedRepoPapers) {
          citation.papers.forEach(function (paper) {
            if (paper.repo && !citation.repo_papers[paper.repo]) {
              citation.repo_papers[paper.repo] = paper;
            }
          });
        }
        result = {
          root: {
            caveats: quality && quality.citation ? (quality.citation.caveats || []) : []
          },
          citation: citation
        };
      }
      // Publish the cursor only after the bounded initial read succeeds.
      // Failures leave a clean handle so the next tab click can retry.
      handle.citationResult = result;
      handle.citationParts = parts;
      handle.nextCitationPart = nextPart;
      handle.citationRepoPapersDerived = derivedRepoPapers;
      handle.citationsLoaded = true;
      return result;
    })();
    handle.citationLoading = loading;
    try {
      return await loading;
    } finally {
      if (handle.citationLoading === loading) {
        handle.citationLoading = null;
      }
    }
  }

  async function loadNextCitationPart(handle) {
    if (!handle.citationsLoaded) await loadCitations(handle);
    if (handle.mode !== "v2" ||
        handle.nextCitationPart >= handle.citationParts.length) {
      return [];
    }
    if (handle.citationPartLoading) return handle.citationPartLoading;
    const ordinal = handle.nextCitationPart;
    const descriptor = handle.citationParts[ordinal];
    const loading = loadJSON(artifactPath(descriptor)).then(function (shard) {
      if (handle.nextCitationPart !== ordinal) {
        throw new Error("citation shard cursor changed during load");
      }
      const rows = shard.rows || [];
      const citation = handle.citationResult && handle.citationResult.citation;
      if (!citation) throw new Error("citation index is unavailable");
      Array.prototype.push.apply(citation.papers, rows);
      if (handle.citationRepoPapersDerived) {
        rows.forEach(function (paper) {
          if (paper.repo && !citation.repo_papers[paper.repo]) {
            citation.repo_papers[paper.repo] = paper;
          }
        });
      }
      handle.nextCitationPart = ordinal + 1;
      return rows;
    }).finally(function () {
      if (handle.citationPartLoading === loading) {
        handle.citationPartLoading = null;
      }
    });
    handle.citationPartLoading = loading;
    return loading;
  }

  async function loadAllCitationParts(handle) {
    await loadCitations(handle);
    while (handle.mode === "v2" &&
           handle.nextCitationPart < handle.citationParts.length) {
      await loadNextCitationPart(handle);
    }
    return handle.citationResult ? handle.citationResult.citation : null;
  }

  global.CXITData = {
    loadHome: loadHome,
    loadExportIndex: loadExportIndex,
    streamExportParts: streamExportParts,
    loadLibrary: loadLibrary,
    loadNextRepositoryPart: loadNextRepositoryPart,
    loadAllRepositoryParts: loadAllRepositoryParts,
    loadCitations: loadCitations,
    loadNextCitationPart: loadNextCitationPart,
    loadAllCitationParts: loadAllCitationParts
  };
})(window);

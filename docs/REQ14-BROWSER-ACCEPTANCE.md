# REQ-14 browser acceptance

Date: 2026-07-28
Fixture release: `f5326377439cf5a0732a` (the migrated, public-only last V1 release)
Browser: Chromium through Playwright CLI 0.1.17
Result: PASS

This is a local, read-only dashboard acceptance run. Python 3.12 served `web/`
on `127.0.0.1`; no discovery, metadata, clone, scan, citation refresh,
publication, or production-data write ran.

## Current-tree browser pass

The final post-hardening pass opened the home page and DALI detail page in a
real Chromium process, exercised both adoption and research tabs, and inspected
every request plus the browser console.

- Home startup requested only `data/v2/manifest.json`. It did not request an
  export, library, repository, quality, or citation artifact.
- Initial DALI navigation requested the manifest, DALI index, and DALI
  repository part only. It rendered 200 of 1,773 rows.
- Opening Research usage then, and only then, requested the quality shard, DALI
  citation index, and DALI citation part. It rendered all 80 available papers.
- There were zero console errors and zero warnings. Every data request returned
  HTTP 200; no unrelated library artifact loaded.

The reproducible command surface was:

```text
python3.12 -m http.server 8765 --bind 127.0.0.1
playwright-cli open http://127.0.0.1:8765/web/index.html
playwright-cli snapshot
playwright-cli click <DALI card>
playwright-cli snapshot
playwright-cli click <Research usage>
playwright-cli snapshot
playwright-cli console
```

The request log proved that no citation or quality artifact was fetched before
the Research usage action. The final console contained zero messages.

## Projected-volume contract pass

The current-source deterministic frontend fixture exercised 600 repositories in
three 200-row shards and 450 papers in three 150-row shards. It did not edit or
publish tracked data.

- Initial navigation loaded one repository shard.
- Each paging action loaded exactly one successor, reaching 200, 400, and 600
  rows.
- A global name sort loaded the remaining current-library shards and produced
  a correct global order without loading another library.
- Research initially loaded one 150-row citation shard. Two paging actions
  reached 300 and 450 rows, then removed the paging control.
- Console errors/warnings and failed data requests were both zero.

## Automated companion checks

`test_req14_frontend.js` locks the request-isolation, paging, sorting, filter
denominator, and complete-export behavior in a fast deterministic fixture. It
is a companion regression suite, not a substitute for the real-browser pass
recorded above.

At final acceptance time the relevant file SHA-256 values were:

```text
data-v2.js   138f4c8889a0aa2ba85dac0e75ee3aa9647a70c799590665e1dd94822e64d216
home.js      407cfad1d9749e9eb4c0b537ede9e1539725aa149fe2754b9d9a0d2dabe9ce2a
library.js   fe52761df2b569c5b4e4282b40b962e324652448d3ac71f762726f393e842610
common.js    9912ab36da5af88c2d61e0342bfcbad233d6e5569562366b0073ecea436fa17f
frontend test be5be3bdcd26411cfd3c8bf1f441f58e3e6513bc8d656951b8648e22bbc8b94d
manifest     32fb5b50a21aa27d03cadb0bcdc422ad8c86ccbcd2b49059375256a45523d424
```

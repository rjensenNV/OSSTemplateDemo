# Vendored browser dependencies

`echarts.min.js` is the unmodified Apache ECharts 5.5.1 browser distribution.
The adjacent license and notice files are copied from the same upstream tag.

To verify the vendored bundle:

```bash
curl -fsSLo /tmp/echarts.min.js \
  https://raw.githubusercontent.com/apache/echarts/5.5.1/dist/echarts.min.js
shasum -a 256 web/vendor/echarts.min.js /tmp/echarts.min.js
```

Both hashes must be
`e84270bd0cd5bdf60fefc26d00c2a391cb2e81f4d26a7a9ee16185a54773a3cf`.

// Pure client helpers shared by the dashboard and pinned by tests.
//
// This file is embedded into the page (see templates.go) and is also loaded
// directly by templates/util_test.js under Node. The UMD wrapper keeps both
// consumers working without a bundler.
//
// IMPORTANT: slugifyName must stay byte-for-byte equivalent to
// config.SlugifyName (internal/config/paths.go); TestDashboardUtilSlugParity
// feeds Go-generated cases through this function to catch drift.
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.GoProx = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Mirrors config.SlugifyName: lowercase, spaces to dashes, strip anything
  // outside [a-z0-9_-], collapse dashes, trim dashes, fall back to "service".
  function slugifyName(name) {
    var slug = String(name == null ? "" : name).trim().toLowerCase().replace(/ /g, "-");
    slug = slug.replace(/[^a-z0-9_-]/g, "").replace(/-+/g, "-").replace(/^-+|-+$/g, "");
    return slug || "service";
  }

  // Mirrors config.AddService's uniqueness loop: append -2, -3, ... until the
  // candidate is unused. existingIDs is an array of already-used IDs.
  function nextServiceID(base, existingIDs) {
    var ids = {};
    (existingIDs || []).forEach(function (id) { ids[id] = true; });
    if (!ids[base]) return base;
    var n = 2;
    while (ids[base + "-" + n]) n++;
    return base + "-" + n;
  }

  // Mirrors AddService's auto-path generation: unique ID first, then "/"+ID,
  // suffixed with -2, -3, ... if another service (e.g. one with a custom
  // path) already owns it. Returns the full path including the leading slash.
  function autoPathFor(baseID, existingIDs, existingPaths) {
    var id = nextServiceID(baseID, existingIDs);
    var basePath = "/" + id;
    var paths = {};
    (existingPaths || []).forEach(function (p) { paths[p] = true; });
    var path = basePath;
    var n = 2;
    while (paths[path]) {
      path = basePath + "-" + n;
      n++;
    }
    return path;
  }

  // Bandwidth: the form shows MB/s; the API stores bytes/s. Empty means
  // unlimited (0); an invalid/negative value returns -1 so callers can flag it.
  function mbToBytes(raw) {
    var text = String(raw == null ? "" : raw).trim();
    if (!text) return 0;
    var mb = Number(text);
    if (!isFinite(mb) || mb < 0) return -1;
    return Math.round(mb * 1048576);
  }

  function bytesToMB(b) {
    if (!b) return "";
    return String(Math.round((b / 1048576) * 1000) / 1000);
  }

  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  return {
    slugifyName: slugifyName,
    nextServiceID: nextServiceID,
    autoPathFor: autoPathFor,
    mbToBytes: mbToBytes,
    bytesToMB: bytesToMB,
    esc: esc
  };
});

(function() {
  var boot = window.__GOPROX_BOOT__ || { username: "", services: [], writable: false };
  var state = { services: boot.services.slice(), writable: !!boot.writable };
  var dragId = null;

  // Pure helpers live in util.js (embedded ahead of this file) so they can be
  // unit-tested under Node; fall back to inert stubs if it did not load.
  var util = window.GoProx || {};
  var esc = util.esc || function(s) { return String(s); };
  var slugifyName = util.slugifyName || function(n) { return String(n); };
  var mbToBytes = util.mbToBytes || function() { return -1; };
  var bytesToMB = util.bytesToMB || function() { return ""; };
  // Server-provided so the client cannot drift from config.DefaultCategory.
  var DEFAULT_CATEGORY = boot.defaultCategory || "未分类";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return [].slice.call((root || document).querySelectorAll(sel)); }

  // Sticky header: the hairline divider appears only once content actually
  // scrolls beneath it (scroll-edge, not a permanent border).
  var header = $(".header");
  if (header) {
    var onScroll = function() { header.classList.toggle("scrolled", window.scrollY > 8); };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  function showToast(msg) {
    var el = $("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(function() { el.classList.remove("show"); }, 2600);
  }

  function setFormError(id, msg) {
    var el = $(id);
    if (!el) return;
    el.textContent = msg || "";
    el.hidden = !msg;
  }

  function jsonFetch(path, opts) {
    return fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}))
      .then(function(res) {
        return res.json().catch(function() { return {}; }).then(function(data) {
          if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
          return data;
        });
      });
  }

  function groupServices(services) {
    var groups = {};
    var order = [];
    services.slice().sort(function(a, b) { return (a.order || 0) - (b.order || 0); }).forEach(function(s) {
      var cat = s.category || DEFAULT_CATEGORY;
      if (!groups[cat]) {
        groups[cat] = [];
        order.push(cat);
      }
      groups[cat].push(s);
    });
    return { groups: groups, order: order };
  }

  function serviceQuery() {
    var el = $("#service-search");
    return el ? el.value.trim().toLowerCase() : "";
  }

  function syncSearchVisibility() {
    var el = $("#service-search");
    if (!el) return;
    el.hidden = state.services.length === 0;
  }

  function renderDashboard() {
    var root = $("#dashboard");
    if (!root) return;
    syncSearchVisibility();
    var q = serviceQuery();
    var visible = state.services.filter(function(s) {
      if (!q) return true;
      var name = (s.name || "").toLowerCase();
      var desc = (s.description || "").toLowerCase();
      return name.indexOf(q) >= 0 || desc.indexOf(q) >= 0;
    });
    var grouped = groupServices(visible);
    var keys = grouped.order;
    root.classList.toggle("is-filtering", !!q);
    if (keys.length === 0) {
      root.innerHTML = q
        ? '<p class="empty">没有匹配的服务。</p>'
        : (state.writable
          ? '<p class="empty">暂无服务。点击右上角 + 添加，点卡片即可访问。</p>'
          : '<p class="empty">暂无服务。</p>');
      bindInteractions();
      return;
    }
    var html = [];
    if (keys.length > 1) {
      html.push('<div class="category-nav">');
      keys.forEach(function(category) {
        html.push('<button type="button" class="category-chip" data-jump="' + esc(category) + '">' + esc(category) + '</button>');
      });
      html.push('</div>');
    }
    keys.forEach(function(category) {
      var items = grouped.groups[category];
      html.push('<section class="category-block" data-category="' + esc(category) + '">');
      html.push('<h2 class="category-title">' + esc(category) + '</h2>');
      html.push('<div class="card-grid" data-drop-zone>');
      items.forEach(function(s, i) { html.push(renderCard(s, i, items.length)); });
      html.push('</div></section>');
    });
    root.innerHTML = html.join("");
    bindInteractions();
  }

  var FAVICON_ONERR = "var e=this,l=e.getAttribute('data-favs').split(' '),i=+(e.getAttribute('data-fav-idx')||0)+1;if(i<l.length){e.setAttribute('data-fav-idx',i);e.src=l[i];}else{e.style.display='none';e.nextElementSibling.style.display='flex';}";

  function renderCard(s, index, total) {
    var proxyUrl = "/proxy/" + encodeURIComponent(boot.username) + s.path + "/";
    var desc = s.description ? '<p class="card-desc">' + esc(s.description) + '</p>' : '';
    var meta = s.websocket ? '<div class="card-meta"><span class="badge ws">WebSocket</span></div>' : '';
    var upDis = index === 0 ? " disabled" : "";
    var downDis = index >= total - 1 ? " disabled" : "";
    var toolbar = state.writable
      ? '<div class="card-toolbar"><span class="drag-handle" draggable="true" data-drag-handle="1" title="拖动排序">⋮⋮</span><div class="card-actions">' +
        '<button type="button" class="card-move" data-move="up" data-move-id="' + esc(s.id) + '" title="上移" aria-label="上移"' + upDis + '>↑</button>' +
        '<button type="button" class="card-move" data-move="down" data-move-id="' + esc(s.id) + '" title="下移" aria-label="下移"' + downDis + '>↓</button>' +
        '<button type="button" class="card-edit" data-edit-id="' + esc(s.id) + '" title="编辑" aria-label="编辑">✎</button>' +
        '<button type="button" class="card-delete" data-delete-id="' + esc(s.id) + '" title="删除" aria-label="删除">×</button>' +
        '</div></div>'
      : '';
    var thumbBase = '/proxy/' + encodeURIComponent(boot.username) + s.path;
    var thumbFavs = [thumbBase + '/favicon.ico', thumbBase + '/favicon.svg', thumbBase + '/favicon.png', thumbBase + '/favicon-32x32.png', thumbBase + '/favicon-16x16.png'];
    var cp = (s.name || '?').codePointAt(0);
    var fl = cp ? String.fromCodePoint(cp).toUpperCase() : '?';
    var favIcon = '<img src="' + esc(thumbFavs[0]) + '" data-favs="' + esc(thumbFavs.join(' ')) + '" data-fav-idx="0" onerror="' + FAVICON_ONERR + '" alt=""><span class="card-letter" data-letter="' + esc(fl) + '">' + esc(fl) + '</span>';
    return '<div class="service-card" data-id="' + esc(s.id) + '" data-category="' + esc(s.category || DEFAULT_CATEGORY) + '">' +
      toolbar +
      '<a class="card-link" href="' + esc(proxyUrl) + '" target="_blank" rel="noopener noreferrer">' +
      '<div class="card-icon">' + favIcon + '</div>' +
      '<div class="card-body"><h2>' + esc(s.name) + '</h2>' +
      desc + meta + '</div></a></div>';
  }

  // Preview-only path resolver: delegates to the shared helper with the
  // currently known service IDs and paths, so the preview mirrors the
  // server's AddService auto-path logic (including path collisions).
  function previewAutoPath(baseID) {
    if (!util.autoPathFor) return "/" + baseID;
    return util.autoPathFor(
      baseID,
      state.services.map(function(s) { return s.id; }),
      state.services.map(function(s) { return s.path; })
    );
  }

  // Find a card by data-id without building a CSS selector from untrusted
  // IDs (hand-written configs may contain quotes, backslashes, brackets).
  function findCard(id) {
    var found = null;
    $$(".service-card").forEach(function(card) {
      if (!found && card.getAttribute("data-id") === id) found = card;
    });
    return found;
  }

  function fillCategoryList() {
    var list = $("#category-options");
    if (!list) return;
    var seen = {};
    var html = [];
    state.services.forEach(function(s) {
      var c = (s.category || "").trim();
      if (!c || seen[c]) return;
      seen[c] = true;
      html.push('<option value="' + esc(c) + '"></option>');
    });
    list.innerHTML = html.join("");
  }

  function updatePathPreview() {
    var el = $("#add-path-preview");
    if (!el) return;
    var custom = ($("#add-path").value || "").trim();
    if (custom) { el.textContent = ""; return; }
    el.textContent = "留空时路径为 " + previewAutoPath(slugifyName($("#add-name").value || ""));
  }

  function updateEditPathPreview() {
    var el = $("#edit-path-preview");
    if (!el) return;
    var custom = ($("#edit-path").value || "").trim();
    el.textContent = custom ? "" : "留空则保持当前路径";
  }

  function collectLayoutItems() {
    var items = [];
    var order = 0;
    $$("#dashboard .category-block").forEach(function(section) {
      var category = section.getAttribute("data-category") || DEFAULT_CATEGORY;
      var normalized = category === DEFAULT_CATEGORY ? undefined : category;
      $$(".service-card", section).forEach(function(card) {
        items.push({ id: card.getAttribute("data-id"), order: order++, category: normalized });
      });
    });
    return items;
  }

  // Layout writes are serialized: one in flight at a time. Without this,
  // rapid move clicks fire concurrent PUTs whose responses can land out of
  // order and paint a layout the server did not settle on.
  var layoutSaving = false;

  function setMoveButtonsDisabled(disabled) {
    $$(".card-move").forEach(function(btn) { btn.disabled = disabled; });
  }

  function saveLayout() {
    if (!state.writable || serviceQuery() || layoutSaving) return Promise.resolve();
    layoutSaving = true;
    setMoveButtonsDisabled(true);
    return jsonFetch("/api/services/layout", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items: collectLayoutItems() })
    }).then(function(data) {
      state.services = data.services || state.services;
      layoutSaving = false;
      renderDashboard();
      showToast("布局已保存");
    }).catch(function(err) {
      // The move/drop was applied optimistically to the DOM. On failure the
      // persisted order is unchanged, so re-render from state before the
      // caller reports the error; otherwise the next render would snap back.
      layoutSaving = false;
      renderDashboard();
      throw err;
    });
  }

  function moveCard(id, dir) {
    if (serviceQuery() || layoutSaving) return;
    var card = findCard(id);
    if (!card || !card.parentNode) return;
    var grid = card.parentNode;
    var cards = $$(".service-card", grid);
    var idx = cards.indexOf(card);
    var dest = idx + dir;
    if (idx < 0 || dest < 0 || dest >= cards.length) return;
    if (dir < 0) grid.insertBefore(card, cards[dest]);
    else grid.insertBefore(card, cards[dest].nextSibling);
    saveLayout().catch(function(err) { showToast(err.message); });
  }

  function bindInteractions() {
    $$(".card-link").forEach(function(link) {
      link.addEventListener("click", function() {
        var card = link.closest(".service-card");
        if (card) {
          card.style.opacity = "0.6";
          setTimeout(function() { card.style.opacity = "1"; }, 1000);
        }
      });
    });

    $$(".category-chip").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var name = btn.getAttribute("data-jump");
        $$(".category-block").forEach(function(section) {
          if (section.getAttribute("data-category") === name) {
            section.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        });
      });
    });

    if (!state.writable) return;

    $$(".card-edit").forEach(function(btn) {
      btn.addEventListener("click", function(ev) {
        ev.preventDefault();
        ev.stopPropagation();
        var id = btn.getAttribute("data-edit-id");
        if (!id) return;
        var svc = state.services.find(function(s) { return s.id === id; });
        if (!svc) return;
        openEditModal(svc);
      });
    });

    $$(".card-delete").forEach(function(btn) {
      btn.addEventListener("click", function(ev) {
        ev.preventDefault();
        ev.stopPropagation();
        var id = btn.getAttribute("data-delete-id");
        if (!id) return;
        var svc = state.services.find(function(s) { return s.id === id; });
        var name = svc && svc.name ? svc.name : id;
        if (!confirm("删除「" + name + "」？\n这只删除转发入口，后端进程仍在运行。")) return;
        jsonFetch("/api/services/" + encodeURIComponent(id), { method: "DELETE" })
          .then(function() {
            state.services = state.services.filter(function(s) { return s.id !== id; });
            renderDashboard();
            showToast("已删除");
          })
          .catch(function(err) { showToast(err.message); });
      });
    });

    $$(".card-move").forEach(function(btn) {
      btn.addEventListener("click", function(ev) {
        ev.preventDefault();
        ev.stopPropagation();
        if (btn.disabled || layoutSaving) return;
        var id = btn.getAttribute("data-move-id");
        var dir = btn.getAttribute("data-move") === "up" ? -1 : 1;
        moveCard(id, dir);
      });
    });

    $$("[data-drag-handle]").forEach(function(handle) {
      handle.addEventListener("dragstart", function(ev) {
        if (serviceQuery() || layoutSaving) {
          ev.preventDefault();
          return;
        }
        var card = handle.closest(".service-card");
        if (!card) return;
        dragId = card.getAttribute("data-id");
        card.classList.add("dragging");
        if (ev.dataTransfer) {
          ev.dataTransfer.effectAllowed = "move";
          ev.dataTransfer.setData("text/plain", dragId);
        }
      });
      handle.addEventListener("dragend", function() {
        var card = handle.closest(".service-card");
        if (card) card.classList.remove("dragging");
        dragId = null;
        $$(".card-grid.drop-target").forEach(function(z) { z.classList.remove("drop-target"); });
      });
    });

    $$("[data-drop-zone]").forEach(function(zone) {
      zone.addEventListener("dragover", function(ev) {
        if (serviceQuery() || layoutSaving) return;
        ev.preventDefault();
        zone.classList.add("drop-target");
      });
      zone.addEventListener("dragleave", function() { zone.classList.remove("drop-target"); });
      zone.addEventListener("drop", function(ev) {
        ev.preventDefault();
        zone.classList.remove("drop-target");
        if (serviceQuery() || layoutSaving) return;
        var id = dragId || (ev.dataTransfer && ev.dataTransfer.getData("text/plain"));
        if (!id) return;
        var card = findCard(id);
        if (!card) return;
        var after = ev.target.closest(".service-card");
        if (after && after !== card) {
          after.parentNode.insertBefore(card, after);
        } else {
          zone.appendChild(card);
        }
        var section = zone.closest(".category-block");
        if (section) card.setAttribute("data-category", section.getAttribute("data-category") || DEFAULT_CATEGORY);
        saveLayout().catch(function(err) { showToast(err.message); });
      });
    });
  }

  function setBusy(form, busy) {
    if (!form) return;
    var btn = form.querySelector('button[type="submit"]');
    if (busy) {
      if (form.getAttribute("data-busy") === "1") return false;
      form.setAttribute("data-busy", "1");
      if (btn) {
        btn.setAttribute("data-label", btn.textContent);
        btn.disabled = true;
        btn.textContent = form.getAttribute("data-busy-label") || "正在保存";
      }
      return true;
    }
    form.removeAttribute("data-busy");
    if (btn) {
      btn.disabled = false;
      btn.textContent = btn.getAttribute("data-label") || btn.textContent;
    }
    return true;
  }

  function categoryValue(id) {
    return ($(id).value || "").trim();
  }

  var modal = $("#add-modal");
  var form = $("#add-form");
  var fab = $("#fab-add");
  function resetAddForm() {
    if (!form) return;
    form.reset();
    $("#add-host").value = "127.0.0.1";
    $("#add-ws").checked = true;
    var adv = $("#add-advanced");
    if (adv) adv.open = false;
    setFormError("#add-error", "");
    setBusy(form, false);
    updatePathPreview();
  }
  if (fab) {
    fab.addEventListener("click", function() {
      closeAccount();
      fillCategoryList();
      resetAddForm();
      modal.classList.add("open");
      $("#add-name").focus();
    });
  }
  var cancel = $("#add-cancel");
  if (cancel) cancel.addEventListener("click", function() { modal.classList.remove("open"); resetAddForm(); });
  if ($("#add-name")) $("#add-name").addEventListener("input", updatePathPreview);
  if ($("#add-path")) $("#add-path").addEventListener("input", updatePathPreview);
  if (form) {
    form.addEventListener("submit", function(ev) {
      ev.preventDefault();
      if (form.getAttribute("data-busy") === "1") return;
      var bw = mbToBytes($("#add-bwlimit").value);
      if (bw < 0) {
        setFormError("#add-error", "带宽请填写不小于 0 的数字");
        return;
      }
      setFormError("#add-error", "");
      if (!setBusy(form, true)) return;
      var path = ($("#add-path").value || "").trim();
      var backendPath = ($("#add-backend-path").value || "").trim();
      var payload = {
        name: $("#add-name").value.trim(),
        description: ($("#add-description").value || "").trim() || undefined,
        host: ($("#add-host").value || "").trim() || "127.0.0.1",
        port: parseInt($("#add-port").value, 10),
        path: path || undefined,
        backend_path: backendPath || undefined,
        bwlimit: bw > 0 ? bw : undefined,
        category: categoryValue("#add-category") || undefined,
        websocket: $("#add-ws").checked
      };
      jsonFetch("/api/services", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }).then(function(data) {
        setBusy(form, false);
        if (data.service) state.services.push(data.service);
        modal.classList.remove("open");
        resetAddForm();
        renderDashboard();
        showToast("已添加");
      }).catch(function(err) {
        setBusy(form, false);
        // Inline only: a toast would duplicate the message and (being above
        // the backdrop) overlap the sheet on short screens.
        setFormError("#add-error", err.message);
      });
    });
  }

  function openEditModal(svc) {
    closeAccount();
    fillCategoryList();
    $("#edit-id").value = svc.id;
    $("#edit-name").value = svc.name || "";
    $("#edit-description").value = svc.description || "";
    $("#edit-host").value = svc.host || "127.0.0.1";
    $("#edit-port").value = svc.port;
    $("#edit-path").value = svc.path || "";
    $("#edit-backend-path").value = svc.backend_path || "";
    editBwOriginalBytes = svc.bwlimit || 0;
    editBwOriginalText = bytesToMB(svc.bwlimit);
    $("#edit-bwlimit").value = editBwOriginalText;
    $("#edit-category").value = svc.category || "";
    $("#edit-ws").checked = !!svc.websocket;
    var adv = $("#edit-advanced");
    if (adv) adv.open = !!(svc.backend_path || svc.bwlimit || !svc.websocket);
    setFormError("#edit-error", "");
    setBusy(editForm, false);
    updateEditPathPreview();
    $("#edit-modal").classList.add("open");
    $("#edit-name").focus();
  }

  var editModal = $("#edit-modal");
  var editForm = $("#edit-form");
  var editCancel = $("#edit-cancel");
  // Keep the exact persisted byte cap so an untouched bandwidth field does not
  // lose precision through the MB display round-trip.
  var editBwOriginalBytes = 0;
  var editBwOriginalText = "";
  if (editCancel) editCancel.addEventListener("click", function() { editModal.classList.remove("open"); });
  if ($("#edit-path")) $("#edit-path").addEventListener("input", updateEditPathPreview);
  if (editForm) {
    editForm.addEventListener("submit", function(ev) {
      ev.preventDefault();
      if (editForm.getAttribute("data-busy") === "1") return;
      var bwText = ($("#edit-bwlimit").value || "").trim();
      var bw = mbToBytes(bwText);
      if (bw < 0) {
        setFormError("#edit-error", "带宽请填写不小于 0 的数字");
        return;
      }
      // Untouched field: send the original bytes back verbatim.
      if (bwText === editBwOriginalText) bw = editBwOriginalBytes;
      setFormError("#edit-error", "");
      if (!setBusy(editForm, true)) return;
      var id = $("#edit-id").value;
      var payload = {};
      payload.name = ($("#edit-name").value || "").trim();
      payload.description = ($("#edit-description").value || "").trim();
      payload.host = ($("#edit-host").value || "").trim() || "127.0.0.1";
      payload.port = parseInt($("#edit-port").value, 10);
      payload.path = ($("#edit-path").value || "").trim();
      payload.backend_path = ($("#edit-backend-path").value || "").trim();
      payload.bwlimit = bw;
      payload.category = categoryValue("#edit-category");
      payload.websocket = $("#edit-ws").checked;

      jsonFetch("/api/services/" + encodeURIComponent(id), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }).then(function(data) {
        setBusy(editForm, false);
        var idx = state.services.findIndex(function(s) { return s.id === id; });
        if (idx >= 0 && data.service) state.services[idx] = data.service;
        editModal.classList.remove("open");
        renderDashboard();
        showToast("已保存");
      }).catch(function(err) {
        setBusy(editForm, false);
        // Inline only; see the add-form catch above.
        setFormError("#edit-error", err.message);
      });
    });
  }

  var accountBtn = $("#account-toggle");
  var accountMenu = $("#account-menu");
  function closeAccount() {
    if (!accountMenu || !accountBtn) return;
    accountMenu.hidden = true;
    accountBtn.setAttribute("aria-expanded", "false");
  }
  if (accountBtn && accountMenu) {
    accountBtn.addEventListener("click", function() {
      var open = accountMenu.hidden;
      accountMenu.hidden = !open;
      accountBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
  var themeBtn = $("#theme-toggle");
  if (themeBtn) themeBtn.addEventListener("click", function() {
    if (window.toggleTheme) window.toggleTheme();
  });

  var search = $("#service-search");
  if (search) search.addEventListener("input", function() { renderDashboard(); });

  document.addEventListener("keydown", function(ev) {
    if (ev.key === "/" && !ev.metaKey && !ev.ctrlKey && !ev.altKey) {
      var tag = (ev.target && ev.target.tagName || "").toLowerCase();
      var typing = tag === "input" || tag === "textarea" || (ev.target && ev.target.isContentEditable);
      if (!typing && search && !search.hidden) {
        ev.preventDefault();
        search.focus();
        return;
      }
    }
    if (ev.key !== "Escape") return;
    if (accountMenu && !accountMenu.hidden) {
      closeAccount();
      return;
    }
    if (modal && modal.classList.contains("open")) {
      modal.classList.remove("open");
      resetAddForm();
    }
    if (editModal && editModal.classList.contains("open")) {
      editModal.classList.remove("open");
    }
  });

  document.addEventListener("click", function(ev) {
    if (!accountMenu || accountMenu.hidden) return;
    if (ev.target.closest && ev.target.closest(".account")) return;
    closeAccount();
  });

  if (modal) {
    modal.addEventListener("click", function(ev) {
      if (ev.target === modal) {
        modal.classList.remove("open");
        resetAddForm();
      }
    });
  }
  if (editModal) {
    editModal.addEventListener("click", function(ev) {
      if (ev.target === editModal) editModal.classList.remove("open");
    });
  }

  jsonFetch("/api/services").then(function(data) {
    state.services = data.services || state.services;
    state.writable = !!data.writable;
    if (!state.writable) {
      var main = document.querySelector(".main");
      if (main) main.classList.add("read-only");
    }
    renderDashboard();
  }).catch(function() { bindInteractions(); });
})();

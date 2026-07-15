(function() {
  var boot = window.__GOPROX_BOOT__ || { username: "", services: [], writable: false };
  var state = { services: boot.services.slice(), writable: !!boot.writable };
  var dragId = null;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return [].slice.call((root || document).querySelectorAll(sel)); }

  function showToast(msg) {
    var el = $("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(function() { el.classList.remove("show"); }, 2600);
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
    services.slice().sort(function(a, b) { return (a.order || 0) - (b.order || 0); }).forEach(function(s) {
      var cat = s.category || "未分类";
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(s);
    });
    return groups;
  }

  function renderDashboard() {
    var root = $("#dashboard");
    if (!root) return;
    var groups = groupServices(state.services);
    var keys = Object.keys(groups);
    if (keys.length === 0) {
      root.innerHTML = '<p class="empty">暂无服务。点击右下角 + 添加，或在终端执行 <code>goprox add</code>。</p>';
      return;
    }
    var html = [];
    keys.forEach(function(category) {
      var items = groups[category];
      html.push('<section class="category-block" data-category="' + esc(category) + '">');
      html.push('<h2 class="category-title">' + esc(category) + '</h2>');
      html.push('<div class="card-grid" data-drop-zone>');
      items.forEach(function(s) { html.push(renderCard(s)); });
      html.push('</div></section>');
    });
    root.innerHTML = html.join("");
    bindInteractions();
  }

  function renderCard(s) {
    var proxyUrl = "/proxy/" + encodeURIComponent(boot.username) + s.path + "/";
    var desc = s.description ? '<p class="card-desc">' + esc(s.description) + '</p>' : '';
    var ws = s.websocket ? '<span class="badge ws">WebSocket</span>' : '';
    var toolbar = state.writable
      ? '<div class="card-toolbar"><span class="drag-handle" draggable="true" data-drag-handle="1" title="拖动排序">⋮⋮</span><div class="card-actions"><button type="button" class="card-edit" data-edit-id="' + esc(s.id) + '" title="编辑">✎</button><button type="button" class="card-delete" data-delete-id="' + esc(s.id) + '" title="删除">×</button></div></div>'
      : '';
    return '<div class="service-card" data-id="' + esc(s.id) + '" data-category="' + esc(s.category || "未分类") + '">' +
      toolbar +
      '<a class="card-link" href="' + esc(proxyUrl) + '" target="_blank" rel="noopener noreferrer"><div class="card-icon">🔗</div><div class="card-body"><h2>' + esc(s.name) + '</h2>' +
      desc + '<div class="card-meta"><span class="endpoint">' + esc(s.host) + ':' + s.port + '</span>' + ws + '</div></div></a></div>';
  }

  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function collectLayoutItems() {
    var items = [];
    var order = 0;
    $$("#dashboard .category-block").forEach(function(section) {
      var category = section.getAttribute("data-category") || "未分类";
      var normalized = category === "未分类" ? undefined : category;
      $$(".service-card", section).forEach(function(card) {
        items.push({ id: card.getAttribute("data-id"), order: order++, category: normalized });
      });
    });
    return items;
  }

  function saveLayout() {
    if (!state.writable) return Promise.resolve();
    return jsonFetch("/api/services/layout", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items: collectLayoutItems() })
    }).then(function(data) {
      state.services = data.services || state.services;
      renderDashboard();
      showToast("布局已保存");
    });
  }

  function bindInteractions() {
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
        if (!id || !confirm("删除服务 " + id + "？")) return;
        jsonFetch("/api/services/" + encodeURIComponent(id), { method: "DELETE" })
          .then(function() {
            state.services = state.services.filter(function(s) { return s.id !== id; });
            renderDashboard();
            showToast("已删除");
          })
          .catch(function(err) { showToast(err.message); });
      });
    });

    $$("[data-drag-handle]").forEach(function(handle) {
      handle.addEventListener("dragstart", function(ev) {
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
        ev.preventDefault();
        zone.classList.add("drop-target");
      });
      zone.addEventListener("dragleave", function() { zone.classList.remove("drop-target"); });
      zone.addEventListener("drop", function(ev) {
        ev.preventDefault();
        zone.classList.remove("drop-target");
        var id = dragId || (ev.dataTransfer && ev.dataTransfer.getData("text/plain"));
        if (!id) return;
        var card = $('.service-card[data-id="' + id + '"]');
        if (!card) return;
        var after = ev.target.closest(".service-card");
        if (after && after !== card) {
          after.parentNode.insertBefore(card, after);
        } else {
          zone.appendChild(card);
        }
        var section = zone.closest(".category-block");
        if (section) card.setAttribute("data-category", section.getAttribute("data-category") || "未分类");
        saveLayout().catch(function(err) { showToast(err.message); });
      });
    });
  }

  var modal = $("#add-modal");
  var form = $("#add-form");
  var fab = $("#fab-add");
  if (fab) {
    fab.addEventListener("click", function() { modal.classList.add("open"); $("#add-name").focus(); });
  }
  var cancel = $("#add-cancel");
  if (cancel) {
    cancel.addEventListener("click", function() { modal.classList.remove("open"); form.reset(); $("#add-host").value = "127.0.0.1"; });
  }
  if (form) {
    form.addEventListener("submit", function(ev) {
      ev.preventDefault();
      var payload = {
        name: $("#add-name").value.trim(),
        description: ($("#add-description").value || "").trim() || undefined,
        host: ($("#add-host").value || "").trim() || "127.0.0.1",
        port: parseInt($("#add-port").value, 10),
        category: ($("#add-category").value || "").trim() || undefined,
        websocket: $("#add-ws").checked
      };
      jsonFetch("/api/services", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }).then(function(data) {
        if (data.service) state.services.push(data.service);
        modal.classList.remove("open");
        form.reset();
        $("#add-host").value = "127.0.0.1";
        renderDashboard();
        showToast("已添加");
      }).catch(function(err) { showToast(err.message); });
    });
  }

  function openEditModal(svc) {
    $("#edit-id").value = svc.id;
    $("#edit-name").value = svc.name || "";
    $("#edit-description").value = svc.description || "";
    $("#edit-host").value = svc.host || "127.0.0.1";
    $("#edit-port").value = svc.port;
    $("#edit-category").value = svc.category || "";
    $("#edit-ws").checked = !!svc.websocket;
    $("#edit-modal").classList.add("open");
    $("#edit-name").focus();
  }

  var editModal = $("#edit-modal");
  var editForm = $("#edit-form");
  var editCancel = $("#edit-cancel");
  if (editCancel) {
    editCancel.addEventListener("click", function() { editModal.classList.remove("open"); });
  }
  if (editForm) {
    editForm.addEventListener("submit", function(ev) {
      ev.preventDefault();
      var id = $("#edit-id").value;
      var payload = {};
      payload.name = ($("#edit-name").value || "").trim();
      payload.description = ($("#edit-description").value || "").trim();
      payload.host = ($("#edit-host").value || "").trim() || "127.0.0.1";
      payload.port = parseInt($("#edit-port").value, 10);
      payload.category = ($("#edit-category").value || "").trim();
      payload.websocket = $("#edit-ws").checked;

      jsonFetch("/api/services/" + encodeURIComponent(id), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }).then(function(data) {
        var idx = state.services.findIndex(function(s) { return s.id === id; });
        if (idx >= 0 && data.service) state.services[idx] = data.service;
        editModal.classList.remove("open");
        renderDashboard();
        showToast("已保存");
      }).catch(function(err) { showToast(err.message); });
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

/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'resources',
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.errorCount > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.errorCount}</span>` : '<span class="chip"><b>Security:</b> OK</span>';
    const warnChip = s.warningCount > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.warningCount}</span>` : '';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(state.name)}</span>
          <span class="kind">Kubernetes YAML · ${fmtSize(s.fileSize)} · 100% offline</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Resources:</b> ${s.resourceCount}</span>
          <span class="chip"><b>Containers:</b> ${s.containerCount}</span>
          <span class="chip"><b>Namespaces:</b> ${s.namespaceCount}</span>
          <span class="chip"><b>Selectors:</b> ${s.selectorCount}</span>
          ${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by kind, name, namespace or image..." />
          <select id="statusFilter">
            <option value="">All statuses</option>
            <option value="error">Has security errors</option>
            <option value="warning">Has warnings</option>
            <option value="ok">Clean</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="resources" type="button">Resources (${s.resourceCount})</button>
          <button class="tab" data-tab="selectors" type="button">Selectors &amp; Labels (${s.selectorCount})</button>
          <button class="tab" data-tab="findings" type="button">Security Checks (${s.errorCount + s.warningCount})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a Kubernetes resource to inspect containers, labels and security checks.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const stSel = document.getElementById('statusFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, status: stSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    stSel.addEventListener('change', runFilter);

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'selectors') {
      pager.style.display = 'none';
      const rows = (s.selectorMatches || []).map((m) => `<tr>
        <td><strong>${esc(m.source)}</strong></td>
        <td>${esc(m.namespace)}</td>
        <td><code>${esc(m.selector)}</code></td>
        <td>${esc(m.targets.join(', ') || '(none)')}</td>
        <td class="${m.status === 'matched' ? 'ok' : 'bad'}">${esc(m.status.toUpperCase())}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th>Source</th><th>Namespace</th><th>Selector</th><th>Matched Workloads</th><th>Status</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="muted">No label selectors in this manifest.</td></tr>'}</tbody>
      </table>`;
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : ''}">${esc(f.severity.toUpperCase())}</td>
        <td>${esc(f.category)}</td>
        <td>${esc(f.resource)}</td>
        <td class="num">${f.line}</td>
        <td>${esc(f.finding)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th class="num">Line</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">All Kubernetes security and reliability checks passed.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const eBadge = r.errorCount ? `<span class="badge-mismatch">ERR (${r.errorCount})</span>` : '';
      const wBadge = r.warningCount ? `<span class="badge-muted">WARN (${r.warningCount})</span>` : '';
      const statusCls = r.status === 'error' ? 'bad' : (r.status === 'ok' ? 'ok' : '');
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.index}</td>
        <td><strong>${esc(r.kind)}</strong></td>
        <td>${esc(r.namespace)}</td>
        <td>${esc(r.name)}${eBadge}${wBadge}</td>
        <td class="num">${r.replicas == null ? '-' : r.replicas}</td>
        <td class="num">${r.containerCount}</td>
        <td class="${statusCls}">${esc(r.status.toUpperCase())}</td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">#</th><th>Kind</th><th>Namespace</th><th>Name</th><th class="num">Replicas</th><th class="num">Containers</th><th>Status</th></tr></thead>
      <tbody>${body || '<tr><td colspan="7" class="muted">No matching resources.</td></tr>'}</tbody>
    </table>`;

    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} resources)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No resource selected.</p>';
      return;
    }
    const pairs = [
      ['Kind', d.kind],
      ['apiVersion', d.apiVersion],
      ['Namespace', d.namespace],
      ['Name', d.name],
      ['Replicas', d.replicas == null ? '-' : String(d.replicas)],
      ['Lines', `L${d.startLine} - L${d.endLine}`],
      ['Status', d.status.toUpperCase()],
    ];
    const rows = pairs.map(([k, v]) => `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`).join('');
    const cRows = (d.containers || []).map((c) => `<tr>
      <td>${esc(c.name)}${c.init ? ' (init)' : ''}</td>
      <td><code>${esc(c.image)}</code></td>
      <td>${esc(c.cpuLimit)} / ${esc(c.memLimit)}</td>
    </tr>`).join('');
    const fItems = (d.findings || []).map((f) => `<li class="${f.severity === 'error' ? 'bad' : ''}"><strong>[${esc(f.severity.toUpperCase())}] ${esc(f.category)}:</strong> ${esc(f.finding)}</li>`).join('');
    el.innerHTML = `
      <div class="dhead"><strong>${esc(d.kind)}/${esc(d.name)}</strong><span class="muted">${esc(d.namespace)}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
      ${cRows ? `<div class="attr-head"><strong>Containers (${d.containers.length})</strong></div><table class="splits"><thead><tr><th>Name</th><th>Image</th><th>CPU / Mem Limit</th></tr></thead><tbody>${cRows}</tbody></table>` : ''}
      ${fItems ? `<div class="attr-head"><strong>Findings (${d.findings.length})</strong></div><ul class="findings-list">${fItems}</ul>` : ''}
      <div class="attr-head"><strong>Manifest YAML</strong></div>
      <pre class="attr-json">${esc(d.rawYaml || '')}</pre>
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} resources.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();

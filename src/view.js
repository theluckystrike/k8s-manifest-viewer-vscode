'use strict';
// View model for Kubernetes Manifest Viewer: pagination, search/filter, selector matches and security findings.

class K8sViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', status: '' };
    this.filtered = parsed.resources.slice();
  }

  summary() {
    const s = this.parsed.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      resourceCount: s.resourceCount,
      containerCount: s.containerCount,
      namespaceCount: s.namespaceCount,
      kindCount: s.kindCount,
      selectorCount: s.selectorCount,
      unmatchedSelectorCount: s.unmatchedSelectorCount,
      securityCount: s.securityCount,
      errorCount: s.errorCount,
      warningCount: s.warningCount,
      selectorMatches: this.parsed.selectorMatches.slice(0, 300),
      findings: this.parsed.findings.slice(0, 400),
    };
  }

  totalCount() {
    return this.parsed.resources.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const status = f && typeof f.status === 'string' ? f.status.trim() : '';
    this.filter = { text, status };
    this.filtered = this.parsed.resources.filter((res) => {
      if (status === 'error' && res.status !== 'error') return false;
      if (status === 'warning' && res.status !== 'warning') return false;
      if (status === 'ok' && res.status !== 'ok') return false;
      if (text) {
        const imgs = res.containers.map((c) => `${c.name} ${c.image}`).join(' ');
        const hay = `${res.kind} ${res.namespace} ${res.name} ${res.apiVersion} ${imgs}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      apiVersion: r.apiVersion,
      kind: r.kind,
      namespace: r.namespace,
      name: r.name,
      replicas: r.replicas,
      containerCount: r.containerCount,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
      status: r.status,
      startLine: r.startLine,
      endLine: r.endLine,
    }));
  }

  detail(index) {
    const r = this.parsed.resources.find((x) => x.index === index) || this.parsed.resources[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      apiVersion: r.apiVersion,
      kind: r.kind,
      namespace: r.namespace,
      name: r.name,
      replicas: r.replicas,
      startLine: r.startLine,
      endLine: r.endLine,
      labels: r.labels,
      podLabels: r.podLabels,
      selector: r.selector,
      containers: r.containers,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
      status: r.status,
      findings: r.findings,
      rawYaml: r.rawYaml,
    };
  }
}

module.exports = { K8sViewModel };

'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseK8sManifest,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryMarkdown,
  buildInventoryCsv,
} = require('../src/k8s');
const { K8sViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

describe('Kubernetes Manifest parser and security checks', () => {
  it('parses multi-document YAML and detects container security issues', () => {
    const yaml = [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'metadata:',
      '  name: web',
      '  namespace: prod',
      'spec:',
      '  replicas: 2',
      '  selector:',
      '    matchLabels:',
      '      app: web',
      '  template:',
      '    metadata:',
      '      labels:',
      '        app: web',
      '    spec:',
      '      containers:',
      '        - name: app',
      '          image: nginx:latest',
      '          securityContext:',
      '            privileged: true',
      '            runAsUser: 0',
      '---',
      'apiVersion: v1',
      'kind: Service',
      'metadata:',
      '  name: web-svc',
      '  namespace: prod',
      'spec:',
      '  selector:',
      '    app: web',
    ].join('\n');
    const parsed = parseK8sManifest(yaml, 'web.k8s.yaml');
    assert.equal(parsed.stats.resourceCount, 2);
    assert.equal(parsed.stats.containerCount, 1);
    assert.ok(parsed.findings.some((f) => f.finding.includes('privileged: true')));
    assert.ok(parsed.findings.some((f) => f.finding.includes('runAsUser: 0')));
    assert.ok(parsed.findings.some((f) => f.finding.includes('resources.limits')));
    assert.ok(parsed.findings.some((f) => f.finding.includes(':latest')));
    assert.equal(parsed.selectorMatches.length, 2);
    assert.ok(parsed.selectorMatches.every((m) => m.status === 'matched'));
  });

  it('flags unmatched Service selector and deprecated apiVersion', () => {
    const yaml = [
      'apiVersion: extensions/v1beta1',
      'kind: Ingress',
      'metadata:',
      '  name: legacy',
      '---',
      'apiVersion: v1',
      'kind: Service',
      'metadata:',
      '  name: orphan',
      'spec:',
      '  selector:',
      '    app: missing-pod',
    ].join('\n');
    const parsed = parseK8sManifest(yaml, 'legacy.yaml');
    assert.ok(parsed.findings.some((f) => f.category === 'Deprecation'));
    assert.ok(parsed.findings.some((f) => f.category === 'Selector'));
    assert.equal(parsed.stats.unmatchedSelectorCount, 1);
  });

  it('parses the bundled sample deployment.k8s.yaml cleanly', () => {
    const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'deployment.k8s.yaml'));
    const parsed = parseK8sManifest(buf, 'deployment.k8s.yaml');
    assert.equal(parsed.stats.resourceCount, 4);
    assert.equal(parsed.stats.containerCount, 2);
    assert.ok(parsed.stats.errorCount >= 1);
    assert.ok(parsed.stats.warningCount >= 1);
  });

  it('builds audit, diff and CSV/Markdown inventory outputs', () => {
    const a = parseK8sManifest('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 2\n', 'staging.yaml');
    const b = parseK8sManifest('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 4\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: api-svc\n', 'prod.yaml');
    const audit = buildAuditMarkdown([{ fileName: 'staging.yaml', parsed: a }]);
    assert.ok(audit.includes('# Kubernetes Manifest Security & Posture Audit'));
    const diff = buildDiffMarkdown('staging.yaml', a, 'prod.yaml', b);
    assert.ok(diff.includes('2 -> 4'));
    assert.ok(diff.includes('| Service/default/api-svc | Added |'));
    const mdInv = buildInventoryMarkdown(b, 'prod.yaml');
    assert.ok(mdInv.includes('# Kubernetes Workload Inventory (prod.yaml)'));
    const csvInv = buildInventoryCsv(b);
    assert.ok(csvInv.includes('apiVersion,kind,namespace,name'));
  });
});

describe('K8sViewModel and HTML CSP', () => {
  it('filters resources and returns detail payload', () => {
    const parsed = parseK8sManifest('apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n', 'app.k8s.yaml');
    const vm = new K8sViewModel(parsed, 'app.k8s.yaml', 120);
    assert.equal(vm.totalCount(), 2);
    assert.equal(vm.setFilter({ text: 'service' }), 1);
    assert.equal(vm.rows(0, 10).length, 1);
    assert.equal(vm.detail(2).name, 'svc');
  });

  it('renders strict CSP without unsafe-inline', () => {
    const policy = csp('vscode-webview://x', 'nonce123');
    assert.ok(policy.includes("default-src 'none'"));
    assert.ok(!policy.includes('unsafe-inline'));
    const html = editorHtml({ cspSource: 'vscode-webview://x', script: 'viewer.js', styleUri: 'viewer.css', title: 'deployment.k8s.yaml', nonce: 'nonce123' });
    assert.ok(html.includes('nonce="nonce123"'));
  });
});

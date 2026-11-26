'use strict';
// Pro tools for Kubernetes Manifest Viewer:
//   1. auditSecurity: Offline Markdown K8s security & best-practice audit across one file or a folder.
//   2. diffManifests: Two-file Kubernetes manifest comparator in Markdown.
//   3. exportInventory: Non-destructive CSV + Markdown workload inventory export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseK8sManifest,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryMarkdown,
  buildInventoryCsv,
} = require('./k8s');

const YAML_FILE_RE = /\.ya?ml$/i;
const YAML_FILTERS = { 'Kubernetes YAML Manifests': ['yaml', 'yml'] };

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Kubernetes manifest') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && YAML_FILE_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: YAML_FILTERS,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listYamlFilesInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && YAML_FILE_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditSecurity(uri, opts = {}) {
    if (!(await pro.allowed('auditSecurity', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listYamlFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No YAML manifest files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      entries.push({ fileName: path.basename(f), parsed: parseK8sManifest(buf, path.basename(f)) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditSecurity');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffManifests(uri, opts = {}) {
    if (!(await pro.allowed('diffManifests', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Kubernetes manifest');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: YAML_FILTERS,
        openLabel: 'Select second Kubernetes manifest to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildDiffMarkdown(
      leftName,
      parseK8sManifest(leftBuf, leftName),
      rightName,
      parseK8sManifest(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffManifests');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportInventory(uri, opts = {}) {
    if (!(await pro.allowed('exportInventory', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseK8sManifest(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/\.ya?ml$/i, '') || 'manifest';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.inventory.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'CSV Workload Inventory': ['csv'] },
        saveLabel: 'Save Kubernetes workload inventory',
      });
    if (!saveUri) return undefined;

    const csvPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(csvPath);
    const stem = path.basename(csvPath, '.csv').replace(/\.inventory$/i, '');
    const mdPath = uniquePath(path.join(dir, `${stem}.inventory.md`));

    fs.writeFileSync(csvPath, buildInventoryCsv(parsed), 'utf8');
    fs.writeFileSync(mdPath, buildInventoryMarkdown(parsed, baseName), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportInventory');
    if (reach) reach.refresh();
    return { files: [csvPath, mdPath], resources: parsed.stats.resourceCount };
  }

  return { auditSecurity, diffManifests, exportInventory };
}

module.exports = { createTools, uniquePath, listYamlFilesInDir };

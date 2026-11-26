'use strict';
// Pure-JS offline Kubernetes multi-document YAML parser, security checker, selector matcher and report builders.
// Zero network calls, zero external dependencies.

const DEPRECATED_APIS = new Set([
  'extensions/v1beta1',
  'apps/v1beta1',
  'apps/v1beta2',
  'networking.k8s.io/v1beta1',
  'policy/v1beta1',
  'batch/v1beta1',
  'rbac.authorization.k8s.io/v1beta1',
  'apiextensions.k8s.io/v1beta1',
]);

const SECRET_KEY_RE = /(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)/i;
const SECRET_VAL_RE = /\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{16,})\b/;
const PLACEHOLDER_RE = /^(?:changeme|placeholder|example|dummy|test|replace[_-]?me|\$\{[^}]+\}|\{\{[^}]+\}\}|<[^>]+>|redacted|xxx+|\*+)$/i;

function stripInlineComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && line[i - 1] !== '\\') inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseScalar(raw) {
  const s = String(raw || '').trim();
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s === 'true' || s === 'True' || s === 'TRUE') return true;
  if (s === 'false' || s === 'False' || s === 'FALSE') return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  if ((s.startsWith('"') && s.endsWith('"') && s.length >= 2) || (s.startsWith("'") && s.endsWith("'") && s.length >= 2)) {
    return s.slice(1, -1);
  }
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitInline(inner).map((item) => parseScalar(item));
  }
  if (s.startsWith('{') && s.endsWith('}')) {
    const inner = s.slice(1, -1).trim();
    const obj = {};
    if (!inner) return obj;
    for (const part of splitInline(inner)) {
      const idx = part.indexOf(':');
      if (idx > 0) {
        const k = parseScalar(part.slice(0, idx));
        const v = parseScalar(part.slice(idx + 1));
        obj[String(k)] = v;
      }
    }
    return obj;
  }
  return s;
}

function splitInline(text) {
  const out = [];
  let cur = '';
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && text[i - 1] !== '\\') inDouble = !inDouble;
    else if (!inSingle && !inDouble) {
      if (ch === '[' || ch === '{') depth += 1;
      else if (ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      else if (ch === ',' && depth === 0) {
        out.push(cur.trim());
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function findKeySep(text) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle && text[i - 1] !== '\\') inDouble = !inDouble;
    else if (ch === ':' && !inSingle && !inDouble) {
      if (i + 1 === text.length || /\s/.test(text[i + 1])) return i;
    }
  }
  return -1;
}

function parseYamlDoc(rawLines, startLineNum) {
  const tokens = [];
  for (let i = 0; i < rawLines.length; i += 1) {
    const clean = stripInlineComment(rawLines[i]).replace(/\t/g, '  ');
    if (!clean.trim()) continue;
    const indent = clean.match(/^ */)[0].length;
    tokens.push({ indent, text: clean.trim(), line: startLineNum + i });
  }
  if (!tokens.length) return null;

  let pos = 0;

  function parseBlock(minIndent) {
    if (pos >= tokens.length || tokens[pos].indent < minIndent) return null;
    if (tokens[pos].text === '-' || tokens[pos].text.startsWith('- ')) {
      return parseSeq(tokens[pos].indent);
    }
    return parseMap(tokens[pos].indent);
  }

  function readBlockScalar(parentIndent) {
    const lines = [];
    while (pos < tokens.length && tokens[pos].indent > parentIndent) {
      lines.push(tokens[pos].text);
      pos += 1;
    }
    return lines.join('\n');
  }

  function parseSeq(seqIndent) {
    const arr = [];
    while (pos < tokens.length) {
      const tok = tokens[pos];
      if (tok.indent < seqIndent) break;
      if (tok.indent > seqIndent) break;
      if (!(tok.text === '-' || tok.text.startsWith('- '))) break;
      const rest = tok.text === '-' ? '' : tok.text.slice(2).trim();
      pos += 1;
      if (!rest) {
        if (pos < tokens.length && tokens[pos].indent > seqIndent) {
          arr.push(parseBlock(tokens[pos].indent));
        } else {
          arr.push(null);
        }
      } else {
        const sep = findKeySep(rest);
        if (sep > 0) {
          const itemObj = {};
          const k = String(parseScalar(rest.slice(0, sep)));
          const vRaw = rest.slice(sep + 1).trim();
          const itemIndent = seqIndent + 2;
          if (!vRaw) {
            if (pos < tokens.length && tokens[pos].indent > itemIndent) {
              itemObj[k] = parseBlock(tokens[pos].indent);
            } else {
              itemObj[k] = null;
            }
          } else if (vRaw === '|' || vRaw === '>' || vRaw === '|-' || vRaw === '>-') {
            itemObj[k] = readBlockScalar(itemIndent);
          } else {
            itemObj[k] = parseScalar(vRaw);
          }
          if (pos < tokens.length && tokens[pos].indent >= itemIndent && !(tokens[pos].indent === seqIndent && tokens[pos].text.startsWith('-'))) {
            const extra = parseMap(tokens[pos].indent);
            if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
              Object.assign(itemObj, extra);
            }
          }
          arr.push(itemObj);
        } else {
          arr.push(parseScalar(rest));
        }
      }
    }
    return arr;
  }

  function parseMap(mapIndent) {
    const obj = {};
    while (pos < tokens.length) {
      const tok = tokens[pos];
      if (tok.indent < mapIndent) break;
      if (tok.indent > mapIndent) {
        pos += 1;
        continue;
      }
      if (tok.text === '-' || tok.text.startsWith('- ')) break;
      const sep = findKeySep(tok.text);
      if (sep <= 0) {
        pos += 1;
        continue;
      }
      const k = String(parseScalar(tok.text.slice(0, sep)));
      const vRaw = tok.text.slice(sep + 1).trim();
      pos += 1;
      if (!vRaw) {
        if (pos < tokens.length && tokens[pos].indent > mapIndent) {
          obj[k] = parseBlock(tokens[pos].indent);
        } else if (pos < tokens.length && tokens[pos].indent === mapIndent && (tokens[pos].text === '-' || tokens[pos].text.startsWith('- '))) {
          obj[k] = parseSeq(mapIndent);
        } else {
          obj[k] = null;
        }
      } else if (vRaw === '|' || vRaw === '>' || vRaw === '|-' || vRaw === '>-') {
        obj[k] = readBlockScalar(mapIndent);
      } else {
        obj[k] = parseScalar(vRaw);
      }
    }
    return obj;
  }

  return parseBlock(tokens[0].indent);
}

function splitYamlDocuments(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const docs = [];
  let cur = [];
  let startLine = 1;

  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (trimmed === '---' || trimmed.startsWith('--- ')) {
      if (cur.some((l) => stripInlineComment(l).trim() !== '')) {
        docs.push({ lines: cur, startLine, endLine: i });
      }
      cur = [];
      startLine = i + 2;
      continue;
    }
    if (trimmed === '...') {
      if (cur.some((l) => stripInlineComment(l).trim() !== '')) {
        docs.push({ lines: cur, startLine, endLine: i });
      }
      cur = [];
      startLine = i + 2;
      continue;
    }
    cur.push(lines[i]);
  }
  if (cur.some((l) => stripInlineComment(l).trim() !== '')) {
    docs.push({ lines: cur, startLine, endLine: lines.length });
  }
  return docs;
}

function extractContainers(obj) {
  if (!obj || typeof obj !== 'object') return [];
  const spec = obj.spec || {};
  const podSpec = (spec.template && spec.template.spec)
    || (spec.jobTemplate && spec.jobTemplate.spec && spec.jobTemplate.spec.template && spec.jobTemplate.spec.template.spec)
    || (obj.kind === 'Pod' ? spec : null);
  if (!podSpec || typeof podSpec !== 'object') return [];
  const regular = Array.isArray(podSpec.containers) ? podSpec.containers.map((c) => ({ ...c, _init: false })) : [];
  const init = Array.isArray(podSpec.initContainers) ? podSpec.initContainers.map((c) => ({ ...c, _init: true })) : [];
  return regular.concat(init).filter((c) => c && typeof c === 'object');
}

function plainMap(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return {};
  const out = {};
  for (const [k, val] of Object.entries(v)) {
    if (val != null && typeof val !== 'object') out[k] = String(val);
  }
  return out;
}

function isSubset(selector, targetLabels) {
  const keys = Object.keys(selector);
  if (!keys.length) return false;
  return keys.every((k) => targetLabels[k] === selector[k]);
}

function parseK8sManifest(input, fileName = 'manifest.k8s.yaml') {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const rawDocs = splitYamlDocuments(text);
  const resources = [];
  const findings = [];

  rawDocs.forEach((rawDoc, idx) => {
    const obj = parseYamlDoc(rawDoc.lines, rawDoc.startLine);
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;

    const apiVersion = typeof obj.apiVersion === 'string' ? obj.apiVersion : 'unknown';
    const kind = typeof obj.kind === 'string' ? obj.kind : 'Unknown';
    const metadata = (obj.metadata && typeof obj.metadata === 'object') ? obj.metadata : {};
    const name = typeof metadata.name === 'string' ? metadata.name : `unnamed-${idx + 1}`;
    const namespace = typeof metadata.namespace === 'string' && metadata.namespace ? metadata.namespace : 'default';
    const spec = (obj.spec && typeof obj.spec === 'object') ? obj.spec : {};
    const replicas = typeof spec.replicas === 'number' ? spec.replicas : null;
    const labels = plainMap(metadata.labels);
    const podLabels = plainMap(spec.template && spec.template.metadata && spec.template.metadata.labels);
    const selector = plainMap((spec.selector && spec.selector.matchLabels) || spec.selector || (spec.podSelector && spec.podSelector.matchLabels));
    const podSec = (spec.template && spec.template.spec && spec.template.spec.securityContext)
      || (kind === 'Pod' && spec.securityContext) || {};
    const containers = extractContainers(obj);
    const resFindings = [];

    const addFinding = (severity, category, message) => {
      const f = {
        severity,
        category,
        resource: `${kind}/${name}`,
        namespace,
        line: rawDoc.startLine,
        finding: message,
      };
      resFindings.push(f);
      findings.push(f);
    };

    if (DEPRECATED_APIS.has(apiVersion)) {
      addFinding('warning', 'Deprecation', `Deprecated apiVersion "${apiVersion}" on ${kind}/${name}.`);
    }

    if (kind === 'Secret' && obj.stringData && typeof obj.stringData === 'object') {
      for (const [sk, sv] of Object.entries(obj.stringData)) {
        const sval = String(sv == null ? '' : sv);
        if (sval && !PLACEHOLDER_RE.test(sval)) {
          addFinding('error', 'Secret', `Plaintext Secret stringData.${sk} detected in ${kind}/${name}.`);
        }
      }
    }

    const containerSummaries = containers.map((c) => {
      const cname = typeof c.name === 'string' ? c.name : 'container';
      const image = typeof c.image === 'string' ? c.image : '';
      const sc = (c.securityContext && typeof c.securityContext === 'object') ? c.securityContext : {};
      const limits = c.resources && c.resources.limits && typeof c.resources.limits === 'object' ? c.resources.limits : null;
      const requests = c.resources && c.resources.requests && typeof c.resources.requests === 'object' ? c.resources.requests : null;

      if (sc.privileged === true) {
        addFinding('error', 'Security', `Container "${cname}" runs with privileged: true.`);
      }
      if (sc.allowPrivilegeEscalation === true) {
        addFinding('error', 'Security', `Container "${cname}" sets allowPrivilegeEscalation: true.`);
      }
      if (sc.runAsUser === 0 || podSec.runAsUser === 0) {
        addFinding('error', 'Security', `Container "${cname}" runs as root (runAsUser: 0).`);
      } else if (sc.runAsNonRoot === false || podSec.runAsNonRoot === false) {
        addFinding('error', 'Security', `Container "${cname}" explicitly allows root (runAsNonRoot: false).`);
      } else if (sc.runAsNonRoot !== true && podSec.runAsNonRoot !== true) {
        addFinding('warning', 'Security', `Container "${cname}" does not set runAsNonRoot: true.`);
      }

      if (!limits || (!limits.cpu && !limits.memory)) {
        addFinding('warning', 'Reliability', `Container "${cname}" is missing resources.limits (cpu/memory).`);
      }

      if (image) {
        const hasTag = image.includes(':') && !image.endsWith(':');
        const hasDigest = image.includes('@sha256:');
        if (image.endsWith(':latest')) {
          addFinding('warning', 'Image', `Container "${cname}" uses mutable :latest tag (${image}).`);
        } else if (!hasTag && !hasDigest) {
          addFinding('warning', 'Image', `Container "${cname}" image "${image}" has no explicit tag or digest.`);
        }
      }

      if (Array.isArray(c.env)) {
        for (const envItem of c.env) {
          if (!envItem || typeof envItem !== 'object') continue;
          const ek = String(envItem.name || '');
          const ev = envItem.value != null ? String(envItem.value) : '';
          if (ev && !PLACEHOLDER_RE.test(ev) && (SECRET_KEY_RE.test(ek) || SECRET_VAL_RE.test(ev))) {
            addFinding('error', 'Secret', `Container "${cname}" env "${ek}" appears to contain a hardcoded secret.`);
          }
        }
      }

      return {
        name: cname,
        image: image || '(none)',
        init: !!c._init,
        privileged: sc.privileged === true,
        runAsNonRoot: sc.runAsNonRoot === true || podSec.runAsNonRoot === true,
        hasLimits: !!(limits && (limits.cpu || limits.memory)),
        cpuLimit: limits && limits.cpu != null ? String(limits.cpu) : '-',
        memLimit: limits && limits.memory != null ? String(limits.memory) : '-',
        cpuRequest: requests && requests.cpu != null ? String(requests.cpu) : '-',
        memRequest: requests && requests.memory != null ? String(requests.memory) : '-',
      };
    });

    const errCount = resFindings.filter((f) => f.severity === 'error').length;
    const warnCount = resFindings.filter((f) => f.severity === 'warning').length;
    const status = errCount > 0 ? 'error' : (warnCount > 0 ? 'warning' : 'ok');

    resources.push({
      index: resources.length + 1,
      apiVersion,
      kind,
      name,
      namespace,
      replicas,
      labels,
      podLabels,
      selector,
      containers: containerSummaries,
      containerCount: containerSummaries.length,
      errorCount: errCount,
      warningCount: warnCount,
      status,
      startLine: rawDoc.startLine,
      endLine: rawDoc.endLine,
      findings: resFindings,
      rawYaml: rawDoc.lines.join('\n'),
    });
  });

  // Selector-to-label matching table across resources in this manifest
  const selectorMatches = [];
  const podTargets = resources.filter((r) => Object.keys(r.podLabels).length > 0 || (r.kind === 'Pod' && Object.keys(r.labels).length > 0));
  for (const src of resources) {
    const selKeys = Object.keys(src.selector);
    if (!selKeys.length) continue;
    const matched = podTargets
      .filter((t) => t.namespace === src.namespace && isSubset(src.selector, Object.keys(t.podLabels).length ? t.podLabels : t.labels))
      .map((t) => `${t.kind}/${t.name}`);
    const matchStatus = matched.length > 0 ? 'matched' : 'unmatched';
    if (matchStatus === 'unmatched' && (src.kind === 'Service' || src.kind === 'NetworkPolicy' || src.kind === 'PodDisruptionBudget')) {
      const f = {
        severity: 'warning',
        category: 'Selector',
        resource: `${src.kind}/${src.name}`,
        namespace: src.namespace,
        line: src.startLine,
        finding: `${src.kind}/${src.name} selector (${selKeys.map((k) => `${k}=${src.selector[k]}`).join(', ')}) matches no pod labels in this file.`,
      };
      src.findings.push(f);
      src.warningCount += 1;
      if (src.status === 'ok') src.status = 'warning';
      findings.push(f);
    }
    selectorMatches.push({
      source: `${src.kind}/${src.name}`,
      namespace: src.namespace,
      selector: selKeys.map((k) => `${k}=${src.selector[k]}`).join(', '),
      targets: matched,
      status: matchStatus,
      line: src.startLine,
    });
  }

  const totalContainers = resources.reduce((sum, r) => sum + r.containerCount, 0);
  const errorCount = findings.filter((f) => f.severity === 'error').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const securityCount = findings.filter((f) => f.category === 'Security' || f.category === 'Secret').length;
  const namespaces = [...new Set(resources.map((r) => r.namespace))];
  const kinds = [...new Set(resources.map((r) => r.kind))];

  return {
    fileName,
    resources,
    selectorMatches,
    findings,
    stats: {
      resourceCount: resources.length,
      containerCount: totalContainers,
      namespaceCount: namespaces.length,
      kindCount: kinds.length,
      selectorCount: selectorMatches.length,
      unmatchedSelectorCount: selectorMatches.filter((m) => m.status === 'unmatched').length,
      securityCount,
      errorCount,
      warningCount,
    },
  };
}

function buildAuditMarkdown(entries) {
  const lines = [
    '# Kubernetes Manifest Security & Posture Audit',
    '',
    `Generated offline on ${new Date().toISOString().slice(0, 10)}.`,
    '',
    '## File Summary',
    '',
    '| File | Resources | Containers | Errors | Warnings | Unmatched Selectors |',
    '| --- | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const e of entries) {
    const s = e.parsed.stats;
    lines.push(`| ${e.fileName} | ${s.resourceCount} | ${s.containerCount} | ${s.errorCount} | ${s.warningCount} | ${s.unmatchedSelectorCount} |`);
  }
  lines.push('', '## Findings', '');
  const allFindings = entries.flatMap((e) => e.parsed.findings.map((f) => ({ file: e.fileName, ...f })));
  if (!allFindings.length) {
    lines.push('All scanned Kubernetes resources passed security and reliability checks.');
  } else {
    lines.push('| File | Severity | Category | Resource | Line | Finding |');
    lines.push('| --- | --- | --- | --- | ---: | --- |');
    for (const f of allFindings) {
      lines.push(`| ${f.file} | ${f.severity.toUpperCase()} | ${f.category} | ${f.resource} | ${f.line} | ${f.finding.replace(/\|/g, '\\|')} |`);
    }
  }
  return lines.join('\n') + '\n';
}

function buildDiffMarkdown(leftName, leftParsed, rightName, rightParsed) {
  const keyOf = (r) => `${r.kind}/${r.namespace}/${r.name}`;
  const leftMap = new Map(leftParsed.resources.map((r) => [keyOf(r), r]));
  const rightMap = new Map(rightParsed.resources.map((r) => [keyOf(r), r]));
  const allKeys = [...new Set([...leftMap.keys(), ...rightMap.keys()])].sort();

  const lines = [
    '# Kubernetes Manifest Comparison',
    '',
    `- Baseline: \`${leftName}\` (${leftParsed.stats.resourceCount} resources, ${leftParsed.stats.errorCount} errors, ${leftParsed.stats.warningCount} warnings)`,
    `- Target: \`${rightName}\` (${rightParsed.stats.resourceCount} resources, ${rightParsed.stats.errorCount} errors, ${rightParsed.stats.warningCount} warnings)`,
    '',
    '| Resource | Change | Replicas | Images | Findings Delta |',
    '| --- | --- | --- | --- | --- |',
  ];

  for (const key of allKeys) {
    const a = leftMap.get(key);
    const b = rightMap.get(key);
    if (!a && b) {
      const imgs = b.containers.map((c) => c.image).join(', ') || '-';
      lines.push(`| ${key} | Added | ${b.replicas == null ? '-' : b.replicas} | ${imgs} | +${b.findings.length} |`);
    } else if (a && !b) {
      const imgs = a.containers.map((c) => c.image).join(', ') || '-';
      lines.push(`| ${key} | Removed | ${a.replicas == null ? '-' : a.replicas} | ${imgs} | -${a.findings.length} |`);
    } else {
      const repChange = a.replicas === b.replicas ? String(b.replicas == null ? '-' : b.replicas) : `${a.replicas == null ? '-' : a.replicas} -> ${b.replicas == null ? '-' : b.replicas}`;
      const aImgs = a.containers.map((c) => c.image).join(', ') || '-';
      const bImgs = b.containers.map((c) => c.image).join(', ') || '-';
      const imgChange = aImgs === bImgs ? bImgs : `${aImgs} -> ${bImgs}`;
      const fDelta = b.findings.length - a.findings.length;
      const status = (a.replicas !== b.replicas || aImgs !== bImgs || fDelta !== 0 || a.rawYaml !== b.rawYaml) ? 'Changed' : 'Unchanged';
      lines.push(`| ${key} | ${status} | ${repChange} | ${imgChange} | ${fDelta >= 0 ? `+${fDelta}` : fDelta} |`);
    }
  }
  return lines.join('\n') + '\n';
}

function buildInventoryMarkdown(parsed, fileName) {
  const lines = [
    `# Kubernetes Workload Inventory (${fileName})`,
    '',
    '| # | Kind | Namespace | Name | Replicas | Containers | Images | Status |',
    '| ---: | --- | --- | --- | ---: | ---: | --- | --- |',
  ];
  for (const r of parsed.resources) {
    const imgs = r.containers.map((c) => c.image).join(', ') || '-';
    lines.push(`| ${r.index} | ${r.kind} | ${r.namespace} | ${r.name} | ${r.replicas == null ? '-' : r.replicas} | ${r.containerCount} | ${imgs.replace(/\|/g, '\\|')} | ${r.status.toUpperCase()} |`);
  }
  return lines.join('\n') + '\n';
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildInventoryCsv(parsed) {
  const header = ['index', 'apiVersion', 'kind', 'namespace', 'name', 'replicas', 'containers', 'images', 'errors', 'warnings', 'status'];
  const rows = parsed.resources.map((r) => [
    r.index,
    r.apiVersion,
    r.kind,
    r.namespace,
    r.name,
    r.replicas == null ? '' : r.replicas,
    r.containerCount,
    r.containers.map((c) => c.image).join('; '),
    r.errorCount,
    r.warningCount,
    r.status,
  ].map(csvCell).join(','));
  return [header.join(','), ...rows].join('\n') + '\n';
}

module.exports = {
  parseYamlDoc,
  splitYamlDocuments,
  parseK8sManifest,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryMarkdown,
  buildInventoryCsv,
};

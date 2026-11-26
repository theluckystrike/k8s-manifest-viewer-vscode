'use strict';
module.exports = {
  prefix: 'zovoK8s',
  triesKey: 'zovoK8s.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditSecurity', title: 'Audit K8s manifest security posture', command: 'zovoK8s.auditSecurity' },
    { id: 'diffManifests', title: 'Compare two Kubernetes manifests', command: 'zovoK8s.diffManifests' },
    { id: 'exportInventory', title: 'Export workload inventory to CSV and Markdown', command: 'zovoK8s.exportInventory' },
  ],
};

const API_BASE = '/api/v1';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export const api = {
  // Pipeline
  analyze: (count = 100) =>
    request('/pipeline/analyze', {
      method: 'POST',
      body: JSON.stringify({ generate_synthetic: count }),
    }),
  getBaselines: () => request('/pipeline/baselines'),

  // Dashboard
  getOverview: () => request('/dashboard/overview'),
  getAlerts: (limit = 50) => request(`/dashboard/alerts?limit=${limit}`),
  getEvents: (limit = 100) => request(`/dashboard/events?limit=${limit}`),

  // Honeynet
  deployHoneynet: () => request('/honeynet/deploy-full', { method: 'POST' }),
  getInstances: () => request('/honeynet/instances'),
  generateDeception: (count = 50) =>
    request(`/honeynet/deception/generate?employee_count=${count}`, { method: 'POST' }),
  mutateHoneynet: () => request('/honeynet/mutate', { method: 'POST' }),

  // Defense
  getFirewallRules: () => request('/defense/firewall-rules'),
  initializeGenetic: () => request('/defense/genetic/initialize', { method: 'POST' }),
  evolveGenetic: () => request('/defense/genetic/evolve', { method: 'POST' }),
  getBestStrategy: () => request('/defense/genetic/best'),
  rotateIPs: () => request('/defense/mtd/rotate-ips', { method: 'POST' }),
  shufflePorts: () => request('/defense/mtd/shuffle-ports', { method: 'POST' }),
  getMTDMappings: () => request('/defense/mtd/mappings'),
  generateMesh: (count = 10) =>
    request(`/defense/distributed/generate-mesh?count=${count}`, { method: 'POST' }),
  getMeshStatus: () => request('/defense/distributed/status'),

  // Red Team
  getPlaybooks: () => request('/red-team/playbooks'),
  runPlaybook: (name) => request(`/red-team/run/${name}`, { method: 'POST' }),
  runAllPlaybooks: () => request('/red-team/run-all', { method: 'POST' }),
  getVulnerabilities: () => request('/red-team/vulnerabilities'),

  // Digital Twin
  createTwin: () => request('/digital-twin/create', { method: 'POST' }),
  getTwinTopology: () => request('/digital-twin/topology'),
  simulateAttack: (attackType) =>
    request('/digital-twin/simulate', {
      method: 'POST',
      body: JSON.stringify({ attack_type: attackType }),
    }),

  // Identity
  assessIdentity: (data) =>
    request('/identity/assess', { method: 'POST', body: JSON.stringify(data) }),
  getProfiles: () => request('/identity/profiles'),
  getHighRisk: () => request('/identity/high-risk'),

  // Threat Intel
  getIntelStats: () => request('/threat-intel/stats'),
  generateSampleIntel: (count = 50) =>
    request(`/threat-intel/generate-sample?count=${count}`, { method: 'POST' }),
  getIndicators: () => request('/threat-intel/indicators'),
};

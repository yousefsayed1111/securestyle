import React, { useState } from 'react'
import { api } from '../../services/api'

export default function NetworkView() {
  const [meshStatus, setMeshStatus] = useState(null)
  const [mtdMappings, setMtdMappings] = useState(null)
  const [geneticResult, setGeneticResult] = useState(null)
  const [firewallRules, setFirewallRules] = useState([])

  const loadFirewall = async () => {
    const data = await api.getFirewallRules()
    setFirewallRules(data.rules || [])
  }

  const initMesh = async () => {
    const data = await api.generateMesh(10)
    setMeshStatus(data)
  }

  const rotateIPs = async () => {
    await api.rotateIPs()
    const data = await api.getMTDMappings()
    setMtdMappings(data)
  }

  const shufflePorts = async () => {
    await api.shufflePorts()
    const data = await api.getMTDMappings()
    setMtdMappings(data)
  }

  const evolveGenetic = async () => {
    await api.initializeGenetic()
    const data = await api.evolveGenetic()
    setGeneticResult(data)
  }

  return (
    <div>
      <div className="page-header">
        <h2>Network Defense</h2>
      </div>

      <div className="stats-grid">
        <ActionCard title="Distributed Mesh" description="Initialize P2P defense nodes" btnLabel="Deploy Mesh" onClick={initMesh} />
        <ActionCard title="IP Rotation" description="Rotate all tracked IPs" btnLabel="Rotate IPs" onClick={rotateIPs} />
        <ActionCard title="Port Shuffling" description="Reassign service ports" btnLabel="Shuffle Ports" onClick={shufflePorts} />
        <ActionCard title="Genetic Evolution" description="Evolve defense strategies" btnLabel="Evolve" onClick={evolveGenetic} />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3>Defense Mesh</h3>
            {meshStatus && <span className="badge low">{meshStatus.active_nodes} active</span>}
          </div>
          {meshStatus?.nodes?.slice(0, 10).map((n, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border)' }}>
              <div>
                <span className="status-dot active" />
                <strong>{n.hostname}</strong>
                <span style={{ color: 'var(--text-muted)', marginLeft: '0.5rem', fontSize: '0.8rem' }}>{n.ip}</span>
              </div>
              <span className="badge low">{n.type}</span>
            </div>
          )) || <p style={{ color: 'var(--text-muted)' }}>Click "Deploy Mesh" to initialize.</p>}
        </div>

        <div className="card">
          <div className="card-header"><h3>Moving Target Defense</h3></div>
          {mtdMappings ? (
            <div>
              <p style={{ color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                {mtdMappings.total_transformations} total transformations
              </p>
              {Object.entries(mtdMappings.ip_mappings || {}).slice(0, 8).map(([orig, cur], i) => (
                <div key={i} style={{ display: 'flex', gap: '1rem', padding: '0.4rem 0', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>{orig}</span>
                  <span style={{ color: 'var(--accent-cyan)' }}>-&gt;</span>
                  <span style={{ color: 'var(--accent-green)' }}>{cur}</span>
                </div>
              ))}
            </div>
          ) : <p style={{ color: 'var(--text-muted)' }}>No transformations yet.</p>}
        </div>
      </div>

      {geneticResult && (
        <div className="card">
          <div className="card-header"><h3>Genetic Algorithm Results</h3></div>
          <div style={{ display: 'flex', gap: '2rem' }}>
            <div><span style={{ color: 'var(--text-muted)' }}>Generation: </span><strong>{geneticResult.generation}</strong></div>
            <div><span style={{ color: 'var(--text-muted)' }}>Best Fitness: </span><strong style={{ color: 'var(--accent-green)' }}>{geneticResult.best_fitness?.toFixed(4)}</strong></div>
            <div><span style={{ color: 'var(--text-muted)' }}>Avg Fitness: </span><strong>{geneticResult.avg_fitness?.toFixed(4)}</strong></div>
            <div><span style={{ color: 'var(--text-muted)' }}>Population: </span><strong>{geneticResult.population_size}</strong></div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>Firewall Rules</h3>
          <button className="btn btn-outline" onClick={loadFirewall}>Load</button>
        </div>
        {firewallRules.length ? (
          <table className="table">
            <thead><tr><th>Action</th><th>Source</th><th>Reason</th></tr></thead>
            <tbody>
              {firewallRules.map((r, i) => (
                <tr key={i}>
                  <td><span className={`badge ${r.action === 'block' ? 'critical' : 'low'}`}>{r.action}</span></td>
                  <td style={{ fontFamily: 'monospace' }}>{r.source}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p style={{ color: 'var(--text-muted)' }}>No rules. Run analysis to generate defensive actions.</p>}
      </div>
    </div>
  )
}

function ActionCard({ title, description, btnLabel, onClick }) {
  return (
    <div className="stat-card" style={{ cursor: 'pointer' }}>
      <div className="label">{title}</div>
      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.5rem 0' }}>{description}</p>
      <button className="btn btn-primary" onClick={onClick}>{btnLabel}</button>
    </div>
  )
}

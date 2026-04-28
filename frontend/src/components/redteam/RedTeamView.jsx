import React, { useState, useEffect } from 'react'
import { api } from '../../services/api'

export default function RedTeamView() {
  const [playbooks, setPlaybooks] = useState({})
  const [results, setResults] = useState([])
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [twin, setTwin] = useState(null)
  const [simResult, setSimResult] = useState(null)
  const [running, setRunning] = useState(false)

  useEffect(() => {
    api.getPlaybooks().then(d => setPlaybooks(d.playbooks || {})).catch(() => {})
  }, [])

  const runAll = async () => {
    setRunning(true)
    try {
      const data = await api.runAllPlaybooks()
      setResults(data.results || [])
      const vulns = await api.getVulnerabilities()
      setVulnerabilities(vulns.vulnerabilities || [])
    } finally {
      setRunning(false)
    }
  }

  const createTwin = async () => {
    const data = await api.createTwin()
    setTwin(data)
  }

  const simulate = async (attackType) => {
    const data = await api.simulateAttack(attackType)
    setSimResult(data)
  }

  return (
    <div>
      <div className="page-header">
        <h2>Red Team & Digital Twin</h2>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3>AI Red Team</h3>
            <button className="btn btn-danger" onClick={runAll} disabled={running}>
              {running ? 'Running...' : 'Run All Playbooks'}
            </button>
          </div>
          <div style={{ marginBottom: '1rem' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Available playbooks:</span>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
              {Object.entries(playbooks).map(([name, desc]) => (
                <span key={name} className="badge medium" title={desc}>{name}</span>
              ))}
            </div>
          </div>
          {results.length > 0 && (
            <table className="table">
              <thead><tr><th>Playbook</th><th>Status</th><th>Steps</th><th>Vulns</th></tr></thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td>{r.simulation?.playbook}</td>
                    <td><span className={`badge ${r.simulation?.status === 'completed' ? 'low' : 'high'}`}>{r.simulation?.status}</span></td>
                    <td>{r.simulation?.steps_completed}</td>
                    <td style={{ color: r.simulation?.vulnerabilities_found > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                      {r.simulation?.vulnerabilities_found}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Digital Twin</h3>
            <button className="btn btn-primary" onClick={createTwin}>Create Twin</button>
          </div>
          {twin ? (
            <div>
              <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>{twin.node_count} nodes in virtual network</p>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                {['port_scan', 'brute_force', 'lateral_movement'].map(t => (
                  <button key={t} className="btn btn-outline" onClick={() => simulate(t)}>Simulate {t}</button>
                ))}
              </div>
              <div style={{ maxHeight: '200px', overflow: 'auto' }}>
                {twin.nodes?.map((n, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.3rem 0', borderBottom: '1px solid var(--border)' }}>
                    <span><span className="status-dot active" />{n.name}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{n.ip}</span>
                    <span className="badge low">{n.type}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : <p style={{ color: 'var(--text-muted)' }}>Create a digital twin to simulate attacks safely.</p>}
        </div>
      </div>

      {simResult && (
        <div className="card">
          <div className="card-header"><h3>Simulation Result</h3></div>
          <div style={{ display: 'flex', gap: '2rem', marginBottom: '1rem' }}>
            <div><span style={{ color: 'var(--text-muted)' }}>Attack: </span><strong>{simResult.attack_type}</strong></div>
            <div><span style={{ color: 'var(--text-muted)' }}>Compromised: </span><strong style={{ color: 'var(--accent-red)' }}>{simResult.compromised_nodes}/{simResult.total_nodes}</strong></div>
            <div><span style={{ color: 'var(--text-muted)' }}>Impact: </span><strong>{simResult.impact_percentage?.toFixed(1)}%</strong></div>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Attack Path:</span>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem', flexWrap: 'wrap' }}>
              {simResult.attack_path?.map((step, i) => (
                <div key={i} style={{ padding: '0.4rem 0.8rem', background: step.success ? 'rgba(239,68,68,0.15)' : 'rgba(34,197,94,0.15)', borderRadius: '6px', fontSize: '0.8rem' }}>
                  {step.node} ({step.ip}) {step.success ? 'COMPROMISED' : 'BLOCKED'}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {vulnerabilities.length > 0 && (
        <div className="card">
          <div className="card-header"><h3>Discovered Vulnerabilities</h3></div>
          <table className="table">
            <thead><tr><th>Type</th><th>Severity</th><th>Asset</th><th>Description</th></tr></thead>
            <tbody>
              {vulnerabilities.map((v, i) => (
                <tr key={i}>
                  <td>{v.type}</td>
                  <td><span className={`badge ${v.severity}`}>{v.severity}</span></td>
                  <td>{v.affected_asset}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{v.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

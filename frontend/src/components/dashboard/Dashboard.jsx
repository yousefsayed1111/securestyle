import React, { useState, useEffect } from 'react'
import { api } from '../../services/api'

export default function Dashboard() {
  const [overview, setOverview] = useState(null)
  const [loading, setLoading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)

  const loadOverview = async () => {
    try {
      setLoading(true)
      const data = await api.getOverview()
      setOverview(data)
    } catch (e) {
      console.error('Failed to load overview:', e)
    } finally {
      setLoading(false)
    }
  }

  const runAnalysis = async () => {
    try {
      setAnalyzing(true)
      await api.analyze(200)
      await loadOverview()
    } catch (e) {
      console.error('Analysis failed:', e)
    } finally {
      setAnalyzing(false)
    }
  }

  useEffect(() => { loadOverview() }, [])

  const counters = overview?.counters || {}

  return (
    <div>
      <div className="page-header">
        <h2>Command Center</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-outline" onClick={loadOverview}>Refresh</button>
          <button className="btn btn-primary" onClick={runAnalysis} disabled={analyzing}>
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </button>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard label="Total Events" value={counters.total_events || 0} color="var(--accent-blue)" />
        <StatCard label="Alerts" value={counters.total_alerts || 0} color="var(--accent-red)" />
        <StatCard label="Blocked" value={counters.defense_action_block || 0} color="var(--accent-orange)" />
        <StatCard label="Redirected" value={counters.defense_action_redirect || 0} color="var(--accent-purple)" />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3>Recent Alerts</h3>
          </div>
          {overview?.recent_alerts?.length ? (
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {overview.recent_alerts.slice(0, 10).map((alert, i) => (
                  <tr key={i}>
                    <td>{alert.type}</td>
                    <td>{alert.source || '-'}</td>
                    <td><span className={`badge ${alert.severity || 'low'}`}>{alert.severity || 'info'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>No alerts yet. Run an analysis to generate data.</p>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Recent Decisions</h3>
          </div>
          {overview?.decision_history?.length ? (
            <table className="table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Action</th>
                  <th>Attack</th>
                </tr>
              </thead>
              <tbody>
                {overview.decision_history.slice(0, 10).map((d, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{d.source_ip}</td>
                    <td><span className={`badge ${d.action}`}>{d.action}</span></td>
                    <td>{d.attack_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>No decisions yet.</p>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Evolution Status</h3>
        </div>
        {overview?.evolution ? (
          <div style={{ display: 'flex', gap: '2rem' }}>
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Rules Generated: </span>
              <strong>{overview.evolution.rules_generated}</strong>
            </div>
            {overview.evolution.thresholds && Object.entries(overview.evolution.thresholds).map(([k, v]) => (
              <div key={k}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{k}: </span>
                <strong>{typeof v === 'number' ? v.toFixed(3) : v}</strong>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  )
}

function StatCard({ label, value, color }) {
  return (
    <div className="stat-card">
      <div className="label">{label}</div>
      <div className="value" style={{ color }}>{typeof value === 'number' ? value.toLocaleString() : value}</div>
    </div>
  )
}

import React, { useState, useEffect } from 'react'
import { api } from '../../services/api'

export default function ThreatView() {
  const [predictions, setPredictions] = useState([])
  const [alerts, setAlerts] = useState([])

  const load = async () => {
    try {
      const [overview, alertData] = await Promise.all([
        api.getOverview(),
        api.getAlerts(30),
      ])
      setPredictions(overview.recent_predictions || [])
      setAlerts(alertData.alerts || [])
    } catch (e) {
      console.error(e)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="page-header">
        <h2>Threat Analysis</h2>
        <button className="btn btn-outline" onClick={load}>Refresh</button>
      </div>

      <div className="card">
        <div className="card-header"><h3>Threat Predictions</h3></div>
        {predictions.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Attack Type</th>
                <th>Probability</th>
                <th>Severity</th>
                <th>Time to Attack</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {predictions.map((p, i) => (
                <tr key={i}>
                  <td>{p.predicted_attack_type}</td>
                  <td>{(p.threat_probability * 100).toFixed(1)}%</td>
                  <td><span className={`badge ${p.severity}`}>{p.severity}</span></td>
                  <td>{p.time_to_attack_seconds ? `${Math.round(p.time_to_attack_seconds)}s` : '-'}</td>
                  <td><span className={`badge ${p.recommended_action}`}>{p.recommended_action}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>No predictions. Run analysis from Dashboard.</p>}
      </div>

      <div className="card">
        <div className="card-header"><h3>Alert Feed</h3></div>
        {alerts.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Source</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 20).map((a, i) => (
                <tr key={i}>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{a.created_at || '-'}</td>
                  <td>{a.type}</td>
                  <td style={{ fontFamily: 'monospace' }}>{a.source || a.source_ip || '-'}</td>
                  <td><span className={`badge ${a.severity || 'low'}`}>{a.severity || 'info'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p style={{ color: 'var(--text-muted)', padding: '1rem' }}>No alerts.</p>}
      </div>
    </div>
  )
}

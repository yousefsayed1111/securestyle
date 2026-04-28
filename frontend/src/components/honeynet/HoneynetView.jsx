import React, { useState } from 'react'
import { api } from '../../services/api'

export default function HoneynetView() {
  const [instances, setInstances] = useState([])
  const [company, setCompany] = useState(null)
  const [intelStats, setIntelStats] = useState(null)

  const deployFull = async () => {
    await api.deployHoneynet()
    const data = await api.getInstances()
    setInstances(data.instances || [])
  }

  const mutate = async () => {
    await api.mutateHoneynet()
    const data = await api.getInstances()
    setInstances(data.instances || [])
  }

  const generateDeception = async () => {
    const data = await api.generateDeception(30)
    setCompany(data)
  }

  const loadIntel = async () => {
    await api.generateSampleIntel(30)
    const data = await api.getIntelStats()
    setIntelStats(data)
  }

  return (
    <div>
      <div className="page-header">
        <h2>Honeynet & Deception</h2>
      </div>

      <div className="stats-grid">
        <ActionCard title="Deploy Honeynet" description="Full environment with Web, SSH, DB, API" btnLabel="Deploy" onClick={deployFull} />
        <ActionCard title="Mutate Services" description="Randomize banners & credentials" btnLabel="Mutate" onClick={mutate} />
        <ActionCard title="Fake Company" description="Generate employees, emails, chat" btnLabel="Generate" onClick={generateDeception} />
        <ActionCard title="Threat Intel" description="Generate sample indicators" btnLabel="Load Intel" onClick={loadIntel} />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h3>Honeypot Instances</h3></div>
          {instances.length ? (
            <table className="table">
              <thead><tr><th>Service</th><th>IP:Port</th><th>Banner</th><th>Interactions</th></tr></thead>
              <tbody>
                {instances.map((inst, i) => (
                  <tr key={i}>
                    <td><span className="badge low">{inst.service_type}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{inst.ip}:{inst.port}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{inst.banner}</td>
                    <td>{inst.interaction_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p style={{ color: 'var(--text-muted)' }}>No instances deployed.</p>}
        </div>

        <div className="card">
          <div className="card-header"><h3>Deception Environment</h3></div>
          {company ? (
            <div>
              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <Metric label="Employees" value={company.employee_count} />
                <Metric label="Emails" value={company.email_count} />
                <Metric label="Chat Messages" value={company.chat_count} />
                <Metric label="Logs" value={company.log_count} />
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {company.departments?.map((d, i) => (
                  <span key={i} className="badge low">{d}</span>
                ))}
              </div>
            </div>
          ) : <p style={{ color: 'var(--text-muted)' }}>Click "Generate" to create a fake company.</p>}
        </div>
      </div>

      {intelStats && (
        <div className="card">
          <div className="card-header"><h3>Threat Intelligence</h3></div>
          <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
            <Metric label="Total Indicators" value={intelStats.total_indicators} />
            {Object.entries(intelStats.by_type || {}).map(([k, v]) => (
              <Metric key={k} label={k} value={v} />
            ))}
            {Object.entries(intelStats.by_severity || {}).map(([k, v]) => (
              <div key={k}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{k}: </span>
                <span className={`badge ${k}`}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Metric({ label, value }) {
  return (
    <div>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{label}: </span>
      <strong>{value}</strong>
    </div>
  )
}

function ActionCard({ title, description, btnLabel, onClick }) {
  return (
    <div className="stat-card">
      <div className="label">{title}</div>
      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.5rem 0' }}>{description}</p>
      <button className="btn btn-primary" onClick={onClick}>{btnLabel}</button>
    </div>
  )
}

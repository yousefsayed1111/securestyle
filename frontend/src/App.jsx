import React, { useState } from 'react'
import Dashboard from './components/dashboard/Dashboard'
import ThreatView from './components/threats/ThreatView'
import NetworkView from './components/network/NetworkView'
import HoneynetView from './components/honeynet/HoneynetView'
import RedTeamView from './components/redteam/RedTeamView'

const NAV_SECTIONS = [
  {
    title: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: '~' },
      { id: 'threats', label: 'Threat Analysis', icon: '!' },
    ],
  },
  {
    title: 'Defense',
    items: [
      { id: 'network', label: 'Network Defense', icon: '#' },
      { id: 'honeynet', label: 'Honeynet / Deception', icon: '>' },
      { id: 'redteam', label: 'Red Team / Twin', icon: '*' },
    ],
  },
]

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard': return <Dashboard />
      case 'threats': return <ThreatView />
      case 'network': return <NetworkView />
      case 'honeynet': return <HoneynetView />
      case 'redteam': return <RedTeamView />
      default: return <Dashboard />
    }
  }

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="sidebar-logo">
          <h1>Sentinel-X</h1>
          <p>Autonomous Cyber Defense</p>
        </div>
        {NAV_SECTIONS.map((section) => (
          <div className="nav-section" key={section.title}>
            <div className="nav-section-title">{section.title}</div>
            {section.items.map((item) => (
              <div
                key={item.id}
                className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                onClick={() => setActivePage(item.id)}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        ))}
        <div className="nav-section" style={{ marginTop: 'auto', borderTop: '1px solid var(--border)', paddingTop: '1rem' }}>
          <div className="nav-section-title">System</div>
          <div className="nav-item">
            <span style={{ fontSize: '0.7rem', color: 'var(--accent-green)' }}>ONLINE</span>
            <span>v1.0.0</span>
          </div>
        </div>
      </nav>
      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  )
}

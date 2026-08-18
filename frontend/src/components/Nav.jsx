export default function Nav({ activeTab, onTabChange }) {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'analysis', label: 'Cost Analysis' },
    { id: 'results', label: 'Optimization Results' },
  ]

  return (
    <div className="nav-shell">
      <nav className="nav">
        <button
          type="button"
          className="nav-brand"
          onClick={() => onTabChange('overview')}
          aria-label="Open CostLens overview"
        >
          <span className="slash">/</span>costlens
          <span className="brand-badge">AWS</span>
        </button>

        <div className="nav-tabs" role="tablist" aria-label="Primary navigation">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="nav-right">
          <button
            type="button"
            className="btn-pill on-light"
            onClick={() => onTabChange('analysis')}
          >
            <span className="dash" />
            COST OPTIMIZER
          </button>
        </div>
      </nav>
    </div>
  )
}
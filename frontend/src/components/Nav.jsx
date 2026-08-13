export default function Nav({ activeTab, onTabChange }) {
  const tabs = [
    { id: 'dashboard-tab', label: 'Overview' },
    { id: 'analysis-tab', label: 'Analysis' },
    { id: 'results-tab', label: 'Results' },
  ]

  return (
    <div className="nav">
      <div className="nav-brand">
        <span className="dot" />
        costlens
      </div>
      <div className="nav-tabs">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => onTabChange(tab.id)}
            role="button"
          >
            {tab.label}
          </div>
        ))}
      </div>
    </div>
  )
}

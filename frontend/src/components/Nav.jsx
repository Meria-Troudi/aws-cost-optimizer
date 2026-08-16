export default function Nav({ activeTab, onTabChange }) {
  // Three tabs instead of the previous five (mockup) vs three (app) mismatch.
  // "Analysis" and "Results" are folded into Overview (which already runs
  // the scan inline via "Run Cost Analysis") and Findings (which already
  // shows the scan output). Recommendations stays separate because it has
  // its own status lifecycle independent of cost monitoring.
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: 'Findings' },
    { id: 'recommendations', label: 'Recommendations' },
  ]

  return (
    <div className="nav">
      <div className="nav-brand">
        <span className="dot" />
        costlens
      </div>
      <div className="nav-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => onTabChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </div>
  )
}
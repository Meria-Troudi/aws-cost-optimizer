import { useMemo, useState } from 'react'
import { serviceStyle } from '../utils/serviceStyle'

function sevClass(s) {
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  if (s === 'info') return 'sev-info'
  return 'sev-low'
}

export default function FindingsTable({ findings, onRowClick }) {
  const [sevFilter, setSevFilter] = useState('all')
  const [svcFilter, setSvcFilter] = useState('all')
  const [resourceFilter, setResourceFilter] = useState('all')

  const entries = useMemo(() => Object.entries(findings), [findings])

  const services = useMemo(
    () => [...new Set(entries.map(([, f]) => f.serviceFilter || f.service))],
    [entries],
  )

  const resources = useMemo(
    () => [...new Set(entries.map(([, f]) => f.resourceLabel))],
    [entries],
  )

  const rows = entries.filter(([, f]) => {
    const sevOk = sevFilter === 'all' || f.severity === sevFilter
    const svcOk = svcFilter === 'all' || f.serviceFilter === svcFilter || f.service === svcFilter
    const resourceOk = resourceFilter === 'all' || f.resourceLabel === resourceFilter
    return sevOk && svcOk && resourceOk
  })

  return (
    <div className="findings-panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">Detected Findings</div>
          <div className="panel-sub">
            Select a row to open evidence, resources, and cost context.
          </div>
        </div>
        <button
          type="button"
          className="small-btn"
          onClick={() => {
            setSevFilter('all')
            setSvcFilter('all')
            setResourceFilter('all')
          }}
        >
          Clear filters
        </button>
      </div>

      <div className="findings-filters">
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          <option value="all">Severity: All</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select value={svcFilter} onChange={(e) => setSvcFilter(e.target.value)}>
          <option value="all">Service: All</option>
          {services.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)}>
          <option value="all">Resource: All</option>
          {resources.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>

      <table className="findings-table">
        <thead>
          <tr>
            <th>Service</th>
            <th>Resource</th>
            <th>Detected condition</th>
            <th>Severity</th>
            <th style={{ textAlign: 'right' }}>Cost</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={5} style={{ textAlign: 'center', color: 'var(--muted)', padding: 20 }}>
                No findings match these filters.
              </td>
            </tr>
          ) : (
            rows.map(([id, f]) => {
              const style = serviceStyle(f.service)
              return (
                <tr key={id} onClick={() => onRowClick(f)}>
                  <td>
                    <div className="fnd-service-cell">
                      <div className="fnd-ico-sm" style={{ background: style.color }}>
                        {style.icon}
                      </div>
                      <div className="fnd-service-name">{f.service}</div>
                    </div>
                  </td>
                  <td className="fnd-resource">{f.resourceLabel}</td>
                  <td className="fnd-title">{f.fullTitle}</td>
                  <td>
                    <span className={`sev-badge ${sevClass(f.severity)}`}>{f.sevLabel}</span>
                  </td>
                  <td className="fnd-savings" style={{ textAlign: 'right' }}>
                    {f.costLabel}
                  </td>
                </tr>
              )
            })
          )}
        </tbody>
      </table>

      <div className="pagination">
        <button type="button" className="page-btn active">
          1
        </button>
      </div>
    </div>
  )
}

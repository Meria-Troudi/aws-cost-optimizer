import { serviceStyle } from '../../utils/serviceStyle'
import { sevLabel, truncateId } from '../../utils/format'

function sevClass(s) {
  if (s === 'high') return 'sev-high'
  if (s === 'medium') return 'sev-medium'
  return 'sev-low'
}

function resourceLabel(finding) {
  const count = finding.resource_count || finding.resourceCount || 1
  if (count > 1) return `${count} resources`
  const id = finding.primary_resource_id || finding.resource_ids?.[0] || finding.resource
  return id ? truncateId(id, 16) : '—'
}

export default function DashboardFindingsTable({ findings, onRowClick }) {
  if (!findings?.length) return null

  return (
    <div className="table-panel section-gap">
      <div className="panel-head">
        <div className="panel-title">Detected Findings</div>
        <div className="panel-icon-btn">⋯</div>
      </div>

      <div className="findings-head-row">
        <span>Resource</span>
        <span>Issue</span>
        <span>Severity</span>
        <span style={{ textAlign: 'right' }}>Cost</span>
      </div>

      {findings.map((f) => {
        const style = serviceStyle(f.service)
        const mapped = {
          id: String(f.id),
          severity: f.severity,
          sevLabel: sevLabel(f.severity),
          service: f.service,
          fullTitle: f.title || f.summary,
          resourceLabel: resourceLabel(f),
          costLabel: f.cost_label || 'Not estimated',
          reason: f.reason,
          ...f,
        }
        return (
          <div
            className="findings-row"
            key={f.id}
            onClick={() => onRowClick?.(mapped)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && onRowClick?.(mapped)}
          >
            <div className="fnd-service">
              <div className="fnd-ico" style={{ background: style.color }}>
                {style.icon}
              </div>
              <div>
                <div className="fnd-service-name">{f.service}</div>
                <div className="fnd-resource">{resourceLabel(f)}</div>
              </div>
            </div>
            <div className="fnd-issue">{f.title || f.summary}</div>
            <span className={`sev-badge ${sevClass(f.severity)}`}>
              {sevLabel(f.severity)}
            </span>
            <div className="fnd-saving">{mapped.costLabel}</div>
          </div>
        )
      })}
    </div>
  )
}

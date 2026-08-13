import { formatMoneyOrDash, formatMonthLabel } from '../../utils/format'

export default function ServiceMonthlyMatrix({ matrix }) {
  const months = matrix?.months || []
  const rows = matrix?.rows || []

  if (!rows.length) return null

  return (
    <div className="table-panel section-gap">
      <div className="panel-head">
        <div>
          <div className="panel-title">Monthly Service Cost</div>
          <div className="panel-sub">Top services by total spend across collected months</div>
        </div>
      </div>
      <div className="matrix-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Service</th>
              {months.map((m) => (
                <th key={m}>{formatMonthLabel(m)}</th>
              ))}
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.service}>
                <td className="matrix-service">{row.service_short || row.service}</td>
                {months.map((m) => (
                  <td key={m} className="mono matrix-cell">
                    {formatMoneyOrDash(row.months?.[m])}
                  </td>
                ))}
                <td className="mono matrix-total">{formatMoneyOrDash(row.total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

import { formatMoneyOrDash } from '../../utils/format'

export default function ServiceRegionMatrix({ matrix }) {
  const regions = matrix?.regions || []
  const rows = matrix?.rows || []

  if (!rows.length) return null

  return (
    <div className="table-panel section-gap">
      <div className="panel-head">
        <div>
          <div className="panel-title">Service × Region</div>
          <div className="panel-sub">Where each service generates spend</div>
        </div>
      </div>
      <div className="matrix-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Service</th>
              {regions.map((r) => (
                <th key={r}>{r}</th>
              ))}
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.service}>
                <td className="matrix-service">{row.service_short || row.service}</td>
                {regions.map((r) => (
                  <td key={r} className="mono matrix-cell">
                    {formatMoneyOrDash(row.regions?.[r])}
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

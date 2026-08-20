import DonutChart from './DonutChart'

function getCost(row) {
  return Number(
    row.current_cost ??
      row.amount ??
      row.cost ??
      0,
  )
}

function getRegionLabel(row) {
  return row.region || row.name || 'Unknown region'
}

export default function RegionMixDonut({ regions }) {
  return (
    <section className="snapshot-panel region-mix-panel">
      <div className="snapshot-panel-head">
        <div>
          <div className="eyebrow">/ Regional Mix</div>
          <h3>Where spend is billed</h3>
        </div>
      </div>

      <DonutChart
        rows={regions}
        getLabel={getRegionLabel}
        getValue={getCost}
        emptyMessage="No regional cost data is available yet."
        ariaLabel="Regional cost mix"
        compact
      />
    </section>
  )
}

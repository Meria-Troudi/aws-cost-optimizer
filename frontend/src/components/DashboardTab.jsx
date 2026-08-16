import CostHeroChart, { HeroBottomFigure } from './dashboard/CostHeroChart'
import CostByServiceGrid from './dashboard/CostByServiceGrid'
import RegionBreakdownPanel from './dashboard/RegionBreakdownPanel'
import ServiceChangesPanel from './dashboard/ServiceChangesPanel'
import PeriodComparisonPanel from './dashboard/PeriodComparisonPanel'
import { formatDate, formatDateTime, formatMoneyOrDash, formatPct } from '../utils/format'

function CostDriversPanelFallback({ drivers, statistics, serviceChanges }) {
  if (!drivers || !drivers.length) return null

  return (
    <div className="panel section-gap">
      <div className="panel-head">
        <div>
          <div className="panel-title">Top Cost Drivers</div>
          <div className="panel-sub">Services contributing to total spend across the period</div>
        </div>
      </div>
      <div className="drivers-grid">
        {drivers.slice(0, 6).map((d) => (
          <div className="driver-row" key={d.service || d.usage_type || d.cost}>
            <div className="driver-name">{d.service_short || d.service || d.usage_type}</div>
            <div className="driver-bar">
              <div
                className="driver-bar-fill"
                style={{ width: `${Math.min(100, d.share_pct || 0)}%` }}
              />
            </div>
            <div className="driver-values">
              <span className="driver-cost mono">{formatMoneyOrDash(d.cost)}</span>
              <span className="driver-share">{(d.share_pct ?? 0).toFixed(1)}%</span>
              {d.change_pct != null && (
                <span className={`driver-change ${d.change_pct >= 0 ? 'up' : 'down'}`}>
                  {formatPct(d.change_pct, true)}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function DashboardTab({
  dashboardData,
  loading,
  refreshing,
  error,
  onRunAnalysis,
  onViewOptimization,
  onRefreshCosts,
}) {
  const hasCost = dashboardData?.cost_available
  const account = dashboardData?.account
  const hero = dashboardData?.hero
  const periods = dashboardData?.periods
  const currentMtd = periods?.current_mtd
  const previousCompleted = periods?.previous_completed_month
  const last3 = periods?.last_3_completed_months
  const completedMom = periods?.completed_month_mom
  const dataFreshness = dashboardData?.data_freshness
  const optimization = dashboardData?.optimization || {}
  const stats = dashboardData?.statistics
  const concentration = dashboardData?.concentration
  const costByService = dashboardData?.cost_by_service || dashboardData?.service_costs || []
  const costByRegion = dashboardData?.cost_by_region || dashboardData?.region_costs || []
  const periodComparison = dashboardData?.period_comparison
  const isAnalyzed = optimization.status === 'analyzed'

  const mtdAvailable = currentMtd?.status === 'available'
  const mtdLabel = currentMtd?.label || 'Current MTD'

  return (
    <>
      <div className="header-row">
        <div className="headline">
          <h1>
            AWS Cost Optimization
            <br />
          </h1>
          <div className="sub">
            {account?.display_name ? (
              <>
                <strong>{account.display_name}</strong>
                {' · '}
                {account.connection_label || 'Connected'}
                {account.region && <> · {account.region}</>}
                {dataFreshness?.cost_through && (
                  <>
                    <br />
                    Cost data through {formatDate(dataFreshness.cost_through)}
                  </>
                )}
                {account.account_id_masked && (
                  <span className="account-masked mono"> · Account {account.account_id_masked}</span>
                )}
              </>
            ) : (
              'Monitor AWS spend, analyze cost drivers, and review optimization opportunities.'
            )}
          </div>
        </div>
        <div className="dashboard-actions">
          <button
            type="button"
            className="small-btn"
            onClick={onRefreshCosts}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing…' : 'Refresh data'}
          </button>
          <button type="button" className="small-btn primary-btn" onClick={onRunAnalysis}>
            Run Cost Analysis
          </button>
        </div>
      </div>

      {loading && !hasCost && <div className="page-loading">Loading cost overview…</div>}
      {error && <div className="page-error">{error}</div>}
      {dashboardData?.data_stale && dashboardData?.data_stale_message && (
        <div className="page-warn section-gap">{dashboardData.data_stale_message}</div>
      )}

      {!loading && !hasCost && !refreshing && !error && (
        <div className="empty-state section-gap">
          <div className="empty-ico">◎</div>
          <h3>No cost data collected</h3>
          <p>
            Cost Explorer data has not been collected yet. Refresh cost data to populate the
            overview, then run a cost analysis for optimization.
          </p>
          <button type="button" className="small-btn primary-btn" onClick={onRefreshCosts}>
            Refresh data
          </button>
        </div>
      )}

      {hasCost && (
        <>
          <div className="kpi-strip section-gap">
            <div className={`kpi-pill ${mtdAvailable ? 'blue' : 'white'}`}>
              <div className="kpi-arrow">{mtdAvailable ? '↗' : '○'}</div>
              <div className="kpi-label">{mtdLabel}</div>
              <div className="kpi-value mono">
                {mtdAvailable ? formatMoneyOrDash(currentMtd.spend) : '—'}
              </div>
              {mtdAvailable && currentMtd.change_vs_previous_mtd_pct != null ? (
                <div
                  className={`kpi-delta ${currentMtd.change_vs_previous_mtd_pct >= 0 ? 'up' : 'down'}`}
                >
                  {formatPct(currentMtd.change_vs_previous_mtd_pct, true)} vs same days last month
                </div>
              ) : (
                <div className="kpi-delta">{currentMtd?.note || currentMtd?.period_label || 'MTD'}</div>
              )}
            </div>
            <div className="kpi-pill white">
              <div className="kpi-label">Forecast</div>
              <div className="kpi-value mono">
                {currentMtd?.forecast != null ? formatMoneyOrDash(currentMtd.forecast) : '—'}
              </div>
              <div className="kpi-delta">
                {currentMtd?.forecast_label || 'Projected full month'}
              </div>
            </div>
            <div className="kpi-pill white">
              <div className="kpi-label">{previousCompleted?.label || 'Previous month'}</div>
              <div className="kpi-value mono">
                {previousCompleted ? formatMoneyOrDash(previousCompleted.spend) : '—'}
              </div>
              <div className="kpi-delta">Completed</div>
            </div>
            <div className="kpi-pill white">
              <div className="kpi-label">3-month spend</div>
              <div className="kpi-value mono">
                {last3 ? formatMoneyOrDash(last3.total_spend) : '—'}
              </div>
              <div className="kpi-delta">{last3?.label || 'Last 3 completed months'}</div>
            </div>
            <div className="kpi-pill slate">
              <div className="kpi-label">Data freshness</div>
              <div className="kpi-value mono" style={{ fontSize: 18 }}>
                {dataFreshness?.cost_through ? formatDate(dataFreshness.cost_through) : '—'}
              </div>
              <div className="kpi-delta">Latest cost data</div>
            </div>
          </div>

          {stats && (
            <div className="stats-row section-gap">
              <div className="stat-chip">
                <span className="stat-k">Total spend</span>
                <span className="stat-v mono">{formatMoneyOrDash(stats.total_spend)}</span>
              </div>
              <div className="stat-chip">
                <span className="stat-k">Avg monthly</span>
                <span className="stat-v mono">{formatMoneyOrDash(stats.average_monthly_spend)}</span>
              </div>
              <div className="stat-chip">
                <span className="stat-k">Highest month</span>
                <span className="stat-v">
                  {stats.highest_month
                    ? `${stats.highest_month.month} · ${formatMoneyOrDash(stats.highest_month.cost)}`
                    : '—'}
                </span>
              </div>
              <div className="stat-chip">
                <span className="stat-k">Lowest month</span>
                <span className="stat-v">
                  {stats.lowest_month
                    ? `${stats.lowest_month.month} · ${formatMoneyOrDash(stats.lowest_month.cost)}`
                    : '—'}
                </span>
              </div>
              <div className="stat-chip">
                <span className="stat-k">Services</span>
                <span className="stat-v mono">{stats.services_with_spend ?? '—'}</span>
              </div>
              <div className="stat-chip">
                <span className="stat-k">Regions</span>
                <span className="stat-v mono">{stats.regions_with_spend ?? '—'}</span>
              </div>
              {completedMom && (
                <div className="stat-chip">
                  <span className="stat-k">Completed MoM</span>
                  <span className="stat-v">
                    {formatPct(completedMom.change_pct, true)} · {completedMom.current_label} vs{' '}
                    {completedMom.previous_label}
                  </span>
                </div>
              )}
              {concentration?.top_3_services_pct != null && (
                <div className="stat-chip">
                  <span className="stat-k">Top 3 services</span>
                  <span className="stat-v mono">{concentration.top_3_services_pct}% of spend</span>
                </div>
              )}
              {concentration?.top_region && (
                <div className="stat-chip">
                  <span className="stat-k">Top region</span>
                  <span className="stat-v">
                    {concentration.top_region} · {concentration.top_region_pct}%
                  </span>
                </div>
              )}
            </div>
          )}

          <PeriodComparisonPanel periodComparison={periodComparison} />

          <div className="grid section-gap">
            <div className="hero-card">
              <div className="hero-top">
                <div className="hero-icon">$</div>
                <div className="hero-expand">↗</div>
              </div>
              <div className="hero-title">{hero?.title || 'Total Cost'}</div>
              <div className="hero-desc">{hero?.description}</div>
              <CostHeroChart hero={hero} forecast={currentMtd?.forecast} />
              <HeroBottomFigure hero={hero} />
            </div>

            <div className="right-col">
              <CostByServiceGrid services={costByService} />
              <RegionBreakdownPanel regionCosts={costByRegion} />
            </div>
          </div>

          <CostDriversPanelFallback
            drivers={dashboardData?.cost_drivers || dashboardData?.top_cost_drivers}
            statistics={stats}
            serviceChanges={dashboardData?.service_changes}
          />

          <ServiceChangesPanel serviceChanges={dashboardData?.service_changes} />

          <div className="panel section-gap optimization-summary">
            <div className="panel-head">
              <div>
                <div className="panel-title">Optimization</div>
                <div className="panel-sub">
                  Separate from cost monitoring — based on the optimization analysis engine
                </div>
              </div>
            </div>
            {isAnalyzed ? (
              <>
                <div className="rec-status" style={{ background: 'var(--green-tint)' }}>
                  <span className="rec-dot" style={{ background: 'var(--green)' }} />
                  <div>
                    <b>Last analysis #{optimization.last_scan_id}</b>
                    <span>
                      {optimization.findings_count} detected finding
                      {optimization.findings_count === 1 ? '' : 's'} ·{' '}
                      {optimization.recommendations_count} recommended action
                      {optimization.recommendations_count === 1 ? '' : 's'}
                    </span>
                  </div>
                </div>
                <button type="button" className="small-btn primary-btn" onClick={onViewOptimization}>
                  View Analysis Results →
                </button>
              </>
            ) : (
              <>
                <div className="rec-status">
                  <span className="rec-dot" />
                  <div>
                    <b>Not analyzed</b>
                    <span>{optimization.message}</span>
                  </div>
                </div>
                <button type="button" className="small-btn primary-btn" onClick={onRunAnalysis}>
                  Run Cost Analysis
                </button>
              </>
            )}
          </div>

          {dashboardData?.last_updated && (
            <div className="data-freshness mono">
              Last updated {formatDateTime(dashboardData.last_updated)}
            </div>
          )}
        </>
      )}
    </>
  )
}

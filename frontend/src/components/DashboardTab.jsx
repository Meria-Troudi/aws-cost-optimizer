import { useMemo, useState } from 'react'

import CostHeroChart, {
  HeroBottomFigure,
} from './dashboard/CostHeroChart'

import CostByServiceTable from './dashboard/CostByServiceTable'
import RegionBreakdownPanel from './dashboard/RegionBreakdownPanel'
import ServiceChangesPanel from './dashboard/ServiceChangesPanel'

import {
  formatDateTime,
  formatDate,
  formatMoneyOrDash,
  formatPct,
} from '../utils/format'

function Kpi({ label, value, note, tone = '' }) {
  return (
    <div className={`overview-kpi ${tone}`}>
      <span className="overview-kpi-label">
        {label}
      </span>

      <strong className="overview-kpi-value mono">
        {value}
      </strong>

      {note && (
        <span className="overview-kpi-note">
          {note}
        </span>
      )}
    </div>
  )
}

function normalizeServiceChange(row) {
  const change =
    row.change_amount ??
    row.difference ??
    null

  const pct =
    row.change_pct ??
    row.percentage_change ??
    null

  const current =
    row.current_cost ??
    row.current_amount ??
    row.cost ??
    null

  return {
    ...row,
    service:
      row.service_short ||
      row.service ||
      row.name ||
      'AWS service',

    cost: current,
    change_amount:
      change != null
        ? Number(change)
        : null,

    change_pct:
      pct != null
        ? Number(pct)
        : null,
  }
}

function adaptDashboard(data) {
  const monthly = Array.isArray(data?.monthly_cost)
    ? data.monthly_cost
    : []

  const current = data?.mtd?.current || {}
  const previous = data?.mtd?.previous || {}

  const changes = Array.isArray(data?.service_changes)
    ? data.service_changes
    : []

  const normalizedChanges = changes.map(
    normalizeServiceChange,
  )

  return {
    current,
    previous,

    monthly,

    hero: {
      trend_points: monthly.map((row) => ({
        month: row.month,
        label: row.month,
        cost: row.amount,

        is_current:
          row.month === current.month,

        is_partial:
          row.month === current.month,
      })),

      total_spend:
        data?.history?.collected_total_spend,

      total_label:
        `${data?.history?.months || 0}-month collected spend`,
    },

    services: Array.isArray(data?.services)
      ? data.services
      : [],

    regions: Array.isArray(data?.regions)
      ? data.regions
      : [],

    changes: {
      increased: normalizedChanges
        .filter(
          (row) =>
            row.change_amount != null &&
            row.change_amount > 0,
        )
        .sort(
          (a, b) =>
            b.change_amount -
            a.change_amount,
        ),

      decreased: normalizedChanges
        .filter(
          (row) =>
            row.change_amount != null &&
            row.change_amount < 0,
        )
        .sort(
          (a, b) =>
            a.change_amount -
            b.change_amount,
        ),

      new: [],
    },
  }
}

function isRunningStatus(status) {
  return [
    'running',
    'pending',
    'queued',
    'analyzing',
  ].includes(
    String(status || '').toLowerCase(),
  )
}

function isDoneStatus(status) {
  return [
    'completed',
    'completed_with_errors',
  ].includes(
    String(status || '').toLowerCase(),
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

  onScanCurrentMonth,
  scanning,
  scanData,
  scanError,
  lastScanId,
}) {
  const [breakdown, setBreakdown] =
    useState('total')

  const [selectedService, setSelectedService] =
    useState('all')

  const [selectedRegion, setSelectedRegion] =
    useState('all')

  const [spendFilters, setSpendFilters] =
    useState({
      period: '3m',
      region: 'all',
      service: 'all',
    })

  const view =
    adaptDashboard(dashboardData)

  const forecast =
    dashboardData?.forecast?.forecast

  const freshness =
    dashboardData?.retrieved_at

  const threeMonths =
    (dashboardData?.monthly_cost || [])
      .slice(-3)
      .reduce(
        (sum, row) =>
          sum + Number(row.amount || 0),
        0,
      )

  const latestScan =
    dashboardData?.latest_scan || null

  const periodLabel =
    dashboardData?.mtd?.current?.month

  /*
   * Scan state
   */
  const liveScan =
    scanData || latestScan

  const scanId =
    liveScan?.id ??
    liveScan?.scan_id ??
    lastScanId

  const scanStatus =
    String(
      liveScan?.status || '',
    ).toLowerCase()

  const scanRunning =
    scanning ||
    isRunningStatus(scanStatus)

  const scanDone =
    isDoneStatus(scanStatus)

  const scanFailed =
    ['failed', 'cancelled'].includes(
      scanStatus,
    )

  const scanProgress = Math.min(
    100,
    Math.max(
      0,
      Number(
        liveScan?.progress_percent,
      ) || 0,
    ),
  )

  const startDate =
    liveScan?.start_date ||
    dashboardData?.mtd?.current?.start_date

  const endDate =
    liveScan?.end_date ||
    dashboardData?.mtd?.current?.end_date

  const findingsCount =
    liveScan?.findings_count ?? 0

  const recommendationsCount =
    liveScan?.recommendations_count ?? 0

  /*
   * Filtered data
   */
  const filteredServices =
    useMemo(() => {
      if (selectedService === 'all') {
        return view.services
      }

      return view.services.filter(
        (service) =>
          service.service ===
            selectedService ||
          service.service_short ===
            selectedService ||
          service.name ===
            selectedService,
      )
    }, [
      view.services,
      selectedService,
    ])

  const filteredRegions =
    useMemo(() => {
      if (selectedRegion === 'all') {
        return view.regions
      }

      return view.regions.filter(
        (region) =>
          region.region ===
            selectedRegion ||
          region.name ===
            selectedRegion,
      )
    }, [
      view.regions,
      selectedRegion,
    ])

  // Keep all hooks above these conditional views. Returning before useMemo
  // after a previous render used it violates React's hook ordering and causes
  // the entire page to disappear when the first dashboard request starts.
  if (loading && !dashboardData) {
    return (
      <div className="dashboard-loading">
        <div className="dashboard-loading-orb" />
        <strong>Loading AWS cost data</strong>
        <span>Connecting to Cost Explorer…</span>
      </div>
    )
  }

  if (error && !dashboardData) {
    return <div className="page-error section-gap">{error}</div>
  }

  if (!dashboardData) {
    return (
      <div className="dashboard-loading">
        <div className="dashboard-loading-orb" />
        <strong>Loading AWS cost data</strong>
        <span>Connecting to Cost Explorer…</span>
      </div>
    )
  }

  return (
  <div className="dashboard-tab">

    {/* =====================================================
        COMMAND HEADER
    ===================================================== */}

    <header className="overview-header">

      <div className="overview-heading">

        <div className="eyebrow">
          / AWS Cost Intelligence
        </div>

        <h1 style={{ fontSize: '1.75rem',color: '#eaedf2', fontWeight: '600' }}>
AWS Cost Overview
        </h1>

     

        <div className="overview-meta">

          <span>
            <b>
              {view.services.length}
            </b>
            {' '}services tracked
          </span>

          <span>
            <b>
              {view.regions.length}
            </b>
            {' '}regions
          </span>

          <span>
            Period{' '}
            <strong className="mono">
              {periodLabel ||
                'Current period'}
            </strong>
          </span>

        </div>

      </div>

      <div className="dashboard-actions">

        <button
          type="button"
          className="small-btn"
          onClick={onRefreshCosts}
          disabled={refreshing}
        >
          <span className="btn-icon">
            ↻
          </span>

          {refreshing
            ? 'Refreshing…'
            : 'Refresh data'}
        </button>

        <button
          type="button"
          className="small-btn primary-btn"
          onClick={onScanCurrentMonth}
          disabled={scanRunning}
        >
          <span className="btn-icon">
            ◉
          </span>

          {scanRunning
            ? 'Scanning…'
            : 'Scan current month'}
        </button>

      </div>

    </header>

    {error && (
      <div className="page-error section-gap">
        {error}
      </div>
    )}

    {scanError && (
      <div className="page-error section-gap">
        {scanError}
      </div>
    )}

    {/* =====================================================
        KPI INTELLIGENCE STRIP
    ===================================================== */}

    <section className="overview-kpis section-gap">

      <Kpi
        label="Current MTD"
        value={formatMoneyOrDash(
          view.current.amount,
        )}
        note={
          view.current.month ||
          'Current period'
        }
        tone="primary"
      />

      <Kpi
        label="Forecast"
        value={formatMoneyOrDash(
          forecast,
        )}
        note="Current month projection"
      />

      <Kpi
        label="Previous MTD"
        value={formatMoneyOrDash(
          view.previous.amount,
        )}
        note={
          view.previous.month ||
          'Previous period'
        }
      />

      <Kpi
        label="3-month spend"
        value={formatMoneyOrDash(
          threeMonths,
        )}
        note="Recent spending"
      />

      <Kpi
        label="Data freshness"
        value={
          freshness
            ? formatDateTime(
                freshness,
              )
            : '—'
        }
        note={
          dashboardData?.source ===
          'aws_cost_explorer'
            ? 'AWS Cost Explorer'
            : 'Cost data source'
        }
      />

    </section>

    {/* =====================================================
        MAIN ANALYTICAL AREA
    ===================================================== */}

    <section className="spend-analysis-panel section-gap">

      <div className="panel-head spend-analysis-head">

        <div>
          <div className="eyebrow">
            / Spend Intelligence
          </div>

          <h2 className="panel-title">
            AWS spend over time
          </h2>

          <p className="panel-sub">
            Move between total spend,
            service concentration, and
            regional exposure without leaving
            the dashboard.
          </p>
        </div>

        

      </div>

      {/* Controls */}

      <div className="spend-filter-bar">

        <div className="spend-filter-group">

          <span className="spend-filter-label">
            Breakdown
          </span>

          <div className="segmented-control">

            {[
              ['total', 'Total'],
              ['service', 'Service'],
              ['region', 'Region'],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={
                  breakdown === id
                    ? 'active'
                    : ''
                }
                onClick={() =>
                  setBreakdown(id)
                }
              >
                {label}
              </button>
            ))}

          </div>

        </div>

        <div className="spend-select">
          <label htmlFor="period-filter">
            Period
          </label>

          <select
            id="period-filter"
            value={spendFilters.period}
            onChange={event =>
              handleFilterChange({
                period:
                  event.target.value,
              })
            }
          >
            <option value="3m">
              Last 3 months
            </option>

            <option value="6m">
              Last 6 months
            </option>

            <option value="12m">
              Last 12 months
            </option>
          </select>
        </div>

        <div className="spend-select">
          <label htmlFor="region-filter">
            Region
          </label>

          <select
            id="region-filter"
            value={spendFilters.region}
            onChange={event =>
              handleFilterChange({
                region:
                  event.target.value,
              })
            }
          >
            <option value="all">
              All regions
            </option>

            {view.regions.map(
              region => {
                const name =
                  region.region ||
                  region.name

                return (
                  <option
                    key={name}
                    value={name}
                  >
                    {name}
                  </option>
                )
              },
            )}
          </select>
        </div>

        <div className="spend-select">
          <label htmlFor="service-filter">
            Service
          </label>

          <select
            id="service-filter"
            value={spendFilters.service}
            onChange={event =>
              handleFilterChange({
                service:
                  event.target.value,
              })
            }
          >
            <option value="all">
              All services
            </option>

            {view.services.map(
              service => {
                const name =
                  service.service_short ||
                  service.service ||
                  service.name

                return (
                  <option
                    key={name}
                    value={name}
                  >
                    {name}
                  </option>
                )
              },
            )}
          </select>
        </div>

      </div>

      {/* Context */}

      <div className="spend-chart-context">

        <span>
          Showing
        </span>

        <strong>
          {spendFilters.region ===
          'all'
            ? 'All regions'
            : spendFilters.region}
        </strong>

        <i>·</i>

        <strong>
          {spendFilters.service ===
          'all'
            ? 'All services'
            : spendFilters.service}
        </strong>

        <i>·</i>

        <strong>
          {spendFilters.period ===
          '3m'
            ? '3 months'
            : spendFilters.period ===
                '6m'
              ? '6 months'
              : '12 months'}
        </strong>

      </div>

      {/* Total chart */}

      {breakdown === 'total' && (
        <div className="total-chart-view">


            <div className="chart-summary-primary">

      
            </div>

            {dashboardData?.mtd
              ?.percentage_change !=
              null && (
              <div
                className={
                  dashboardData.mtd
                    .percentage_change >=
                  0
                    ? 'chart-change up'
                    : 'chart-change down'
                }
              >
              

            
              </div>
            )}

            <div className="chart-summary-mini">
            
            </div>

          

          <CostHeroChart
            hero={view.hero}
            forecast={forecast}
            filters={spendFilters}
          />

          <HeroBottomFigure
            hero={view.hero}
          />

        </div>
      )}

      {/* Service visualization */}

      {breakdown === 'service' && (
        <div className="breakdown-chart-view">

          <div className="breakdown-view-title">
            <div>
              <span className="eyebrow">
                / Service View
              </span>

              <strong>
                Current service spend
              </strong>
            </div>

            <span>
              {filteredServices.length}
              {' '}services
            </span>
          </div>

          <div className="horizontal-cost-bars">

            {filteredServices
              .slice(0, 10)
              .map(service => {
                const name =
                  service.service_short ||
                  service.service ||
                  service.name ||
                  'AWS service'

                const amount =
                  Number(
                    service.current_cost ??
                      service.amount ??
                      service.current_amount ??
                      0,
                  )

                const max =
                  Math.max(
                    ...filteredServices.map(
                      item =>
                        Number(
                          item.current_cost ??
                            item.amount ??
                            item.current_amount ??
                            0,
                        ),
                    ),
                    1,
                  )

                return (
                  <div
                    className="cost-bar-row"
                    key={name}
                  >
                    <div className="cost-bar-label">
                      <span>
                        {name}
                      </span>

                      <strong className="mono">
                        {formatMoneyOrDash(
                          amount,
                        )}
                      </strong>
                    </div>

                    <div className="cost-bar-track">
                      <div
                        className="cost-bar-fill"
                        style={{
                          width: `${
                            (amount /
                              max) *
                            100
                          }%`,
                        }}
                      />
                    </div>
                  </div>
                )
              })}

          </div>
        </div>
      )}

      {/* Region visualization */}

      {breakdown === 'region' && (
        <div className="breakdown-chart-view">

          <div className="breakdown-view-title">
            <div>
              <span className="eyebrow">
                / Regional View
              </span>

              <strong>
                Current regional spend
              </strong>
            </div>

            <span>
              {filteredRegions.length}
              {' '}regions
            </span>
          </div>

          <div className="horizontal-cost-bars">

            {filteredRegions
              .slice(0, 10)
              .map(region => {
                const name =
                  region.region ||
                  region.name ||
                  'Unknown region'

                const amount =
                  Number(
                    region.cost ??
                      region.current_cost ??
                      region.amount ??
                      0,
                  )

                const max =
                  Math.max(
                    ...filteredRegions.map(
                      item =>
                        Number(
                          item.cost ??
                            item.current_cost ??
                            item.amount ??
                            0,
                        ),
                    ),
                    1,
                  )

                return (
                  <div
                    className="cost-bar-row"
                    key={name}
                  >
                    <div className="cost-bar-label">
                      <span>
                        {name}
                      </span>

                      <strong className="mono">
                        {formatMoneyOrDash(
                          amount,
                        )}
                      </strong>
                    </div>

                    <div className="cost-bar-track">
                      <div
                        className="cost-bar-fill region"
                        style={{
                          width: `${
                            (amount /
                              max) *
                            100
                          }%`,
                        }}
                      />
                    </div>
                  </div>
                )
              })}

          </div>
        </div>
      )}

    </section>

    {/* =====================================================
        SERVICE + REGION INTELLIGENCE
    ===================================================== */}

    <section className="dashboard-grid section-gap">

      <CostByServiceTable
        services={view.services}
      />

      <RegionBreakdownPanel
        regionCosts={view.regions}
      />

    </section>

    {/* =====================================================
        MOVEMENTS
    ===================================================== */}

    <ServiceChangesPanel
      serviceChanges={view.changes}
    />

    {/* =====================================================
        OPTIMIZATION ENGINE
    ===================================================== */}

    <section className="panel optimization-panel section-gap">

      <div className="panel-head">

        <div>
          <div className="eyebrow">
            / Optimization Engine
          </div>

          <h2 className="panel-title">
            Find the next savings opportunity
          </h2>

          <p className="panel-sub">
            Resource analysis, utilization
            checks, billing reconciliation,
            and optimization recommendations.
          </p>
        </div>

        {liveScan && (
          <div className="analysis-status">
            <span className="status-pulse" />
            {scanRunning
              ? 'Analysis running'
              : scanDone
                ? 'Analysis complete'
                : scanFailed
                  ? 'Analysis failed'
                  : 'Ready'}
          </div>
        )}

      </div>

      {!liveScan &&
        !scanRunning && (
          <div className="scan-empty">

            <div className="optimization-empty-icon">
              ✦
            </div>

            <div className="scan-empty-copy">
              <span className="eyebrow">
                Ready to analyze
              </span>

              <strong>
                No optimization analysis yet
              </strong>

              <p>
                Run an analysis to identify
                waste, underutilized resources,
                and potential savings.
              </p>
            </div>

            <button
              type="button"
              className="small-btn primary-btn"
              onClick={
                onScanCurrentMonth
              }
            >
              Analyze current month
            </button>

          </div>
        )}

      {scanRunning && (
        <div className="scan-progress">

          <div className="scan-progress-head">
            <div>
              <span>
                Optimization engine
              </span>

              <strong>
                Analyzing AWS environment
              </strong>
            </div>

            <b>
              {Math.round(
                scanProgress,
              )}%
            </b>
          </div>

          <div className="scan-progress-track">
            <div
              className="scan-progress-fill"
              style={{
                width: `${
                  scanProgress || 8
                }%`,
              }}
            />
          </div>

          <div className="scan-stage-grid">

            <span className="complete">
              ✓ Resources
            </span>

            <span className="complete">
              ✓ Billing
            </span>

            <span className="active">
              ◌ Utilization
            </span>

            <span>
              ◯ Recommendations
            </span>

          </div>

          <p className="scan-progress-note">
            Collecting resources,
            utilization, billing
            reconciliation, and running
            optimization analyzers.
          </p>

        </div>
      )}

      {scanDone && liveScan && (
        <div className="scan-completed">

          <div className="scan-result-summary">

            <div className="scan-result-icon">
              ✓
            </div>

            <div>
              <span className="eyebrow">
                Analysis complete
              </span>

              <strong>
                {scanStatus ===
                'completed_with_errors'
                  ? 'Completed with warnings'
                  : 'Optimization analysis completed'}
              </strong>

              <p>
                {findingsCount}
                {' '}finding
                {findingsCount === 1
                  ? ''
                  : 's'}
                {' · '}
                {recommendationsCount}
                {' '}recommendation
                {recommendationsCount === 1
                  ? ''
                  : 's'}
              </p>
            </div>

          </div>

          <div className="scan-result-metrics">

            <div>
              <span>Findings</span>
              <strong>
                {findingsCount}
              </strong>
            </div>

            <div>
              <span>Recommendations</span>
              <strong>
                {recommendationsCount}
              </strong>
            </div>

          </div>

          <div className="dashboard-actions">

            <button
              type="button"
              className="small-btn primary-btn"
              onClick={() =>
                scanId &&
                onViewOptimization(
                  scanId,
                )
              }
            >
              View recommendations 
            </button>

            <button
              type="button"
              className="small-btn"
              onClick={
                onScanCurrentMonth
              }
              disabled={scanRunning}
            >
              Run again
            </button>

          </div>

        </div>
      )}

      {scanFailed &&
        liveScan && (
          <div className="scan-empty failed">

            <div className="optimization-empty-icon">
              !
            </div>

            <div>
              <strong>
                Analysis could not be completed
              </strong>

              <p>
                {liveScan?.error ||
                  'The optimization scan failed. Please try again.'}
              </p>
            </div>

            <button
              type="button"
              className="small-btn primary-btn"
              onClick={
                onScanCurrentMonth
              }
            >
              Try again
            </button>

          </div>
        )}

      <div className="scan-advanced">

        <button
          type="button"
          className="small-btn"
          onClick={
            onRunAnalysis
          }
        >
          Advanced analysis 
        </button>

        <span className="panel-sub">
          Configure dates, regions, and
          cost thresholds for a deeper
          investigation.
        </span>

      </div>

    </section>

  </div>
)
}

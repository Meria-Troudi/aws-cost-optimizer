import {
  formatDateTime,
  formatMoneyOrDash,
  formatPct,
  pluralize,
} from '../utils/format'
import {
  isRunningStatus,
  isDoneStatus,
  isFailedStatus,
} from '../utils/scanStatus'

import CostHeroChart from './dashboard/CostHeroChart'
import RegionMixDonut from './dashboard/RegionMixDonut'
import CostDriversPanel from './dashboard/CostDriversPanel'
import ServiceChangesPanel from './dashboard/ServiceChangesPanel'


function Kpi({
  label,
  value,
  note,
  tone = '',
}) {

  return (
    <div
      className={`overview-kpi ${tone}`}
    >

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


function adaptDashboard(
  data,
) {

  const monthly =
    Array.isArray(
      data?.monthly_cost,
    )
      ? data.monthly_cost
      : []

  const current =
    data?.mtd?.current ||
    {}

  const changes =
    Array.isArray(
      data?.service_changes,
    )
      ? data.service_changes
      : []

  const normalizedChanges =
    changes.map(
      row => {

        const change =
          row.change_amount ??
          row.difference ??
          null

        const pct =
          row.change_pct ??
          row.percentage_change ??
          null

        const currentCost =
          row.current_cost ??
          row.cost ??
          null

        return {
          ...row,
          service:
            row.service ||
            'AWS service',
          cost:
            currentCost,
          change_amount:
            change != null
              ? Number(change)
              : null,
          change_pct:
            pct != null
              ? Number(pct)
              : null,
        }
      },
    )

  return {

    current,

    monthly,

    hero: {
      trend_points:
        monthly.map(
          row => ({
            month:
              row.month,
            label:
              row.month,
            cost:
              row.amount,
            is_current:
              row.month ===
              current.month,
            is_partial:
              row.month ===
              current.month,
          }),
        ),

      total_spend:
        data?.history
          ?.collected_total_spend,

      total_label:
        `${data?.history?.months || 0}-month spend`,
    },

    services:
      Array.isArray(
        data?.services,
      )
        ? data.services
        : [],

    regions:
      Array.isArray(
        data?.regions,
      )
        ? data.regions
        : [],

    changes: {
      increased:
        normalizedChanges
          .filter(
            row =>
              row.change_amount != null &&
              row.change_amount >
                0,
          )
          .sort(
            (a, b) =>
              b.change_amount -
              a.change_amount,
          ),

      decreased:
        normalizedChanges
          .filter(
            row =>
              row.change_amount != null &&
              row.change_amount <
                0,
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


const SCAN_STAGES = [
  {
    label: 'Resources',
    threshold: 25,
  },
  {
    label: 'Billing',
    threshold: 65,
  },
  {
    label: 'Utilization',
    threshold: 90,
  },
  {
    label: 'Recommendations',
    threshold: 100,
  },
]


function scanStageStatus(
  progress,
  threshold,
  index,
) {

  if (
    progress >= threshold
  ) {
    return 'complete'
  }

  const previous =
    index === 0
      ? 0
      : SCAN_STAGES[
          index - 1
        ].threshold

  if (
    progress >= previous
  ) {
    return 'active'
  }

  return 'pending'
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

  const view =
    adaptDashboard(
      dashboardData,
    )

  const forecastInfo =
    dashboardData?.forecast

  const forecast =
    forecastInfo?.forecast

  const freshness =
    dashboardData?.retrieved_at

  const liveScan =
    scanData ||
    dashboardData?.latest_scan ||
    null

  const scanId =
    liveScan?.id ??
    liveScan?.scan_id ??
    lastScanId

  const scanStatus =
    String(
      liveScan?.status ||
        '',
    ).toLowerCase()

  const scanRunning =
    scanning ||
    isRunningStatus(
      scanStatus,
    )

  const scanDone =
    isDoneStatus(
      scanStatus,
    )

  const scanFailed =
    isFailedStatus(
      scanStatus,
    )

  const scanProgress =
    Math.min(
      100,
      Math.max(
        0,
        Number(
          liveScan?.progress_percent,
        ) || 0,
      ),
    )

  const findingsCount =
    liveScan?.findings_count ??
    0

  const recommendationsCount =
    liveScan?.recommendations_count ??
    0

  const historySpend =
    (
      dashboardData
        ?.monthly_cost || []
    ).reduce(
      (
        sum,
        row,
      ) =>
        sum +
        Number(
          row.amount || 0,
        ),
      0,
    )

  if (
    loading &&
    !dashboardData
  ) {

    return (
      <div className="dashboard-loading">

        <div className="dashboard-loading-orb" />

        <strong>
          Loading AWS cost data
        </strong>

        <span>
          Connecting to Cost Explorer…
        </span>

      </div>
    )
  }

  if (
    error &&
    !dashboardData
  ) {

    return (
      <div className="page-error section-gap">
        {error}
      </div>
    )
  }

  if (!dashboardData) {

    return (
      <div className="dashboard-loading">

        <div className="dashboard-loading-orb" />

        <strong>
          Loading AWS cost data
        </strong>

        <span>
          Connecting to Cost Explorer…
        </span>

      </div>
    )
  }

  function handleRefresh() {

    onRefreshCosts?.({
      history_months: 6,
      force_refresh: true,
    })
  }

  return (
    <div className="dashboard-tab">

      {/* -----------------------------------------------------
          HEADER
      ----------------------------------------------------- */}

      <header className="overview-header">

        <div className="overview-heading">

          <div className="eyebrow">
            / AWS Cost Intelligence
          </div>

          <h1>
            AWS Cost Overview
          </h1>

          <div className="overview-meta-line">

            <span>
              Cost Explorer
            </span>

            <span>
              ·
            </span>

            <span>
              Updated{' '}
              {freshness
                ? formatDateTime(
                    freshness,
                  )
                : '—'}
            </span>

            <span>
              ·
            </span>

            <span>
              Live billing view
            </span>

          </div>

        </div>

        <div className="dashboard-actions">

          <button
            type="button"
            className="small-btn"
            onClick={
              handleRefresh
            }
            disabled={
              refreshing
            }
          >
            ↻{' '}
            {refreshing
              ? 'Refreshing…'
              : 'Refresh data'}
          </button>

          <button
            type="button"
            className="small-btn primary-btn"
            onClick={
              onScanCurrentMonth
            }
            disabled={
              scanRunning
            }
          >
            ◉{' '}
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

      {/* -----------------------------------------------------
          LIVE KPI STRIP
      ----------------------------------------------------- */}

      <section className="overview-kpis section-gap">

        <Kpi
          label="Current MTD"
          value={formatMoneyOrDash(
            view.current.amount,
          )}
          note={
            view.current.month ||
            'Current month'
          }
          tone="primary"
        />

        <Kpi
          label="Forecast"
          value={formatMoneyOrDash(
            forecast,
          )}
          note="AWS Cost Explorer forecast"
        />

        <Kpi
          label="Vs previous month"
          value={formatPct(
            dashboardData
              ?.mtd
              ?.percentage_change,
            true,
          )}
          note={
            dashboardData
              ?.mtd
              ?.difference != null
              ? `${formatMoneyOrDash(
                  dashboardData.mtd.difference,
                )} difference`
              : 'No comparison'
          }
        />

        <Kpi
          label="6-month spend"
          value={formatMoneyOrDash(
            historySpend,
          )}
          note="Historical spend"
        />

      </section>

      {/* -----------------------------------------------------
          MAIN TREND + REGION
      ----------------------------------------------------- */}

      <section className="spend-main-grid section-gap">

        <div className="panel spend-analysis-panel">

          <div className="panel-head">

            <div>

              <div className="eyebrow">
                / Spend Intelligence
              </div>

              <h2 className="panel-title">
                AWS spend over time
              </h2>

              <p className="panel-sub">
                Current month, recent history and
                AWS Cost Explorer forecast.
              </p>

            </div>

          </div>

          <CostHeroChart
            hero={
              view.hero
            }
            forecast={
              forecast
            }
            forecastInfo={
              forecastInfo
            }
          />

        </div>

        <RegionMixDonut
          regions={
            view.regions
          }
        />

      </section>

      {/* -----------------------------------------------------
          SINGLE COST EXPLORER
      ----------------------------------------------------- */}

      <CostDriversPanel />

      {/* -----------------------------------------------------
          MOVEMENTS
      ----------------------------------------------------- */}

      <ServiceChangesPanel
        serviceChanges={
          view.changes
        }
      />

      {/* -----------------------------------------------------
          OPTIMIZATION
      ----------------------------------------------------- */}

      <section className="panel optimization-panel optimization-panel-compact section-gap">

        <div className="panel-head">

          <div>

            <div className="eyebrow">
              / Optimization
            </div>

            <h2 className="panel-title">
              Find the next savings opportunity
            </h2>

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
                  and optimization opportunities.
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
                )}
                %
              </b>

            </div>

            <div className="scan-progress-track">

              <div
                className="scan-progress-fill"
                style={{
                  width: `${
                    scanProgress ||
                    8
                  }%`,
                }}
              />

            </div>

            <div className="scan-stage-grid">

              {SCAN_STAGES.map(
                (
                  stage,
                  index,
                ) => {

                  const status =
                    scanStageStatus(
                      scanProgress,
                      stage.threshold,
                      index,
                    )

                  return (
                    <span
                      key={
                        stage.label
                      }
                      className={
                        status ===
                        'pending'
                          ? ''
                          : status
                      }
                    >
                      {status ===
                      'complete'
                        ? '✓'
                        : status ===
                            'active'
                          ? '◌'
                          : '◯'}{' '}
                      {stage.label}
                    </span>
                  )
                },
              )}

            </div>

          </div>
        )}

        {scanDone &&
          liveScan && (
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
                    {pluralize(
                      findingsCount,
                      'finding',
                    )}
                    {' · '}
                    {pluralize(
                      recommendationsCount,
                      'recommendation',
                    )}
                  </p>

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
                    'The optimization scan failed.'}
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
            Configure dates, regions and
            thresholds for deeper analysis.
          </span>

        </div>

        {scanId && (
          <div className="optimization-footer">

            <button
              type="button"
              className="optimization-footer-link"
              onClick={() =>
                onViewOptimization(
                  scanId,
                )
              }
            >
              View optimization results →
            </button>

          </div>
        )}

      </section>

    </div>
  )
}
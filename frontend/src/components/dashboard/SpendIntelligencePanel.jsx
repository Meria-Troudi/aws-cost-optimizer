import { useEffect, useMemo, useState } from 'react'

import { getDailyTrend } from '../../api/client'

import { formatDate, formatMoneyOrDash } from '../../utils/format'

import { Kpi } from '../DashboardTab'

import CostHeroChart from './CostHeroChart'

const GRANULARITY_OPTIONS = [
  { value: 'monthly', label: 'Monthly' },
  { value: 7, label: '7D' },
  { value: 14, label: '14D' },
  { value: 30, label: '30D' },
]

export default function SpendIntelligencePanel({
  hero,
  forecast,
  forecastInfo,
}) {
  const [granularity, setGranularity] = useState('monthly')

  const [dailyData, setDailyData] = useState(null)
  const [dailyLoading, setDailyLoading] = useState(false)
  const [dailyError, setDailyError] = useState(null)

  const isDaily = granularity !== 'monthly'

  useEffect(() => {
    if (!isDaily) return undefined

    let active = true

    setDailyLoading(true)
    setDailyError(null)

    getDailyTrend({ days: granularity })
      .then((response) => {
        if (!active) return
        setDailyData(response)
      })
      .catch((err) => {
        if (!active) return
        setDailyError(err.message || 'Unable to load daily cost trend.')
      })
      .finally(() => {
        if (!active) return
        setDailyLoading(false)
      })

    return () => {
      active = false
    }
  }, [granularity, isDaily])

  const dailyHero = useMemo(() => {
    const points = Array.isArray(dailyData?.points) ? dailyData.points : []

    return {
      trend_points: points.map((point) => ({
        date: point.date,
        label: formatDate(point.date),
        cost: point.cost,
        is_current: point.is_current,
        is_partial: point.is_partial,
      })),
    }
  }, [dailyData])

  return (
    <div className="panel spend-analysis-panel">
      <div className="panel-head">
        <div>
          <div className="eyebrow">/ Spend Intelligence</div>

          <h2 className="panel-title">AWS spend over time</h2>

          <p className="panel-sub">
            {isDaily
              ? 'Rolling daily spend from AWS Cost Explorer.'
              : 'Current month, recent history and AWS Cost Explorer forecast.'}
          </p>
        </div>

        <div className="cost-explorer-segmented spend-granularity-toggle">
          {GRANULARITY_OPTIONS.map((option) => (
            <button
              type="button"
              key={option.value}
              className={granularity === option.value ? 'active' : ''}
              onClick={() => setGranularity(option.value)}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {isDaily && (
        <div className="overview-kpis daily-trend-kpi">
          <Kpi
            label={`Total cost (${granularity}D)`}
            value={formatMoneyOrDash(dailyData?.total_cost)}
            note={
              dailyData?.start_date && dailyData?.end_date
                ? `${formatDate(dailyData.start_date)} → ${formatDate(dailyData.end_date)}`
                : 'Rolling window'
            }
            tone="primary"
          />
        </div>
      )}

      {isDaily && dailyError ? (
        <div className="page-error">{dailyError}</div>
      ) : isDaily && dailyLoading && !dailyData ? (
        <div className="chart-empty">
          <span className="chart-empty-icon">&#8721;</span>
          <strong>Loading daily trend&hellip;</strong>
        </div>
      ) : (
        <CostHeroChart
          hero={isDaily ? dailyHero : hero}
          forecast={isDaily ? null : forecast}
          forecastInfo={isDaily ? null : forecastInfo}
          partialLabel={isDaily ? 'Today' : 'MTD'}
        />
      )}
    </div>
  )
}

import { useEffect, useMemo, useState } from 'react'

import {
  formatCompact,
  formatMoneyOrDash,
} from '../../utils/format'

const CHART_W = 1160
const CHART_H = 250

function buildSmoothPath(points) {
  if (points.length < 2) return ''

  let path = `M ${points[0].cx},${points[0].cy}`

  for (let i = 1; i < points.length; i += 1) {
    const previous = points[i - 1]
    const current = points[i]

    const cpx = (previous.cx + current.cx) / 2

    path +=
      ` C ${cpx},${previous.cy} ` +
      `${cpx},${current.cy} ` +
      `${current.cx},${current.cy}`
  }

  return path
}

function getPointLabel(point) {
  return (
    point.label ||
    point.month ||
    point.date ||
    ''
  )
}

export default function CostHeroChart({
  hero,
  forecast,
  filters,
}) {
  const [activeIdx, setActiveIdx] = useState(null)
  const [mounted, setMounted] = useState(false)

  const points = Array.isArray(hero?.trend_points)
    ? hero.trend_points
    : []

  const activeFilterLabel = useMemo(() => {
    if (!filters) return null

    const parts = []

    if (
      filters.region &&
      filters.region !== 'all'
    ) {
      parts.push(filters.region)
    }

    if (
      filters.service &&
      filters.service !== 'all'
    ) {
      parts.push(filters.service)
    }

    if (
      filters.period &&
      filters.period !== '3m'
    ) {
      const periodMap = {
        '6m': 'Last 6 months',
        '12m': 'Last 12 months',
        custom: 'Custom range',
      }

      parts.push(
        periodMap[filters.period] ||
          filters.period,
      )
    }

    return parts.length
      ? parts.join(' · ')
      : null
  }, [filters])

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      setMounted(true)
    })

    return () => cancelAnimationFrame(frame)
  }, [hero?.trend_points])

  const bars = useMemo(() => {
    if (!points.length) return []

    const maxCost = Math.max(
      ...points.map(
        point => Number(point.cost) || 0,
      ),
      1,
    )

    const gap = CHART_W / points.length

    const width = Math.min(
      30,
      Math.max(12, gap * 0.52),
    )

    return points.map((point, index) => {
      const cost =
        Number(point.cost) || 0

      const height = Math.max(
        8,
        (cost / maxCost) * 180,
      )

      const x =
        index * gap +
        (gap - width) / 2

      const y = CHART_H - height

      return {
        ...point,
        cost,
        x,
        y,
        h: height,
        barW: width,
        cx: x + width / 2,
        cy: y,
        index,
        delay: `${index * 0.045}s`,
      }
    })
  }, [points, forecast])

  useEffect(() => {
    if (!bars.length) {
      setActiveIdx(null)
      return
    }

    const currentIndex = bars.findIndex(
      bar => bar.is_current,
    )

    setActiveIdx(
      currentIndex >= 0
        ? currentIndex
        : bars.length - 1,
    )
  }, [bars])

  if (!bars.length) {
    return (
      <div className="hero-chart">
        <div className="chart-empty">
          <span className="chart-empty-icon">
            ∿
          </span>
          <strong>
            No trend data available
          </strong>
          <span>
            Cost Explorer has not returned
            enough history for this chart yet.
          </span>
        </div>
      </div>
    )
  }

  const linePath = buildSmoothPath(bars)

  const areaPath =
    `${linePath} ` +
    `L ${bars[bars.length - 1].cx},${CHART_H} ` +
    `L ${bars[0].cx},${CHART_H} Z`

  const activeBar =
    activeIdx != null
      ? bars[activeIdx]
      : bars[bars.length - 1]

  return (
    <div className="hero-chart">

      <div className="hero-chart-grid">
        <span />
        <span />
        <span />
        <span />
      </div>

      {activeBar && (
        <div
          className="hero-badge mono hero-badge-animated"
          style={{
            left: `${
              (activeBar.cx / CHART_W) * 100
            }%`,
          }}
        >
          <span>
            {formatMoneyOrDash(
              activeBar.cost,
            )}
          </span>

          {activeBar.is_partial && (
            <small>MTD</small>
          )}
        </div>
      )}

      <svg
        className="hero-svg"
        viewBox={`0 0 ${CHART_W} ${CHART_H}`}
        preserveAspectRatio="none"
        aria-label="AWS cost trend chart"
        role="img"
      >
        <defs>
          <linearGradient
            id="costLensHeroFill"
            x1="0"
            y1="0"
            x2="0"
            y2="1"
          >
            <stop
              offset="0%"
              stopColor="#E8394B"
              stopOpacity=".34"
            />

            <stop
              offset="100%"
              stopColor="#E8394B"
              stopOpacity="0"
            />
          </linearGradient>
        </defs>

        <path
          className="hero-area"
          d={areaPath}
          fill="url(#costLensHeroFill)"
        />

        {bars.map(bar => (
          <rect
            key={`hist-${bar.index}`}
            className={`hero-histogram ${
              bar.is_current
                ? 'current'
                : ''
            }`}
            x={bar.x}
            y={CHART_H - Math.max(
              14,
              bar.h * 0.45,
            )}
            width={bar.barW}
            height={Math.max(
              14,
              bar.h * 0.45,
            )}
            rx="4"
          />
        ))}

        <path
          className={`hero-line ${
            mounted
              ? 'hero-line-drawn'
              : ''
          }`}
          d={linePath}
          fill="none"
          stroke="#E8394B"
          strokeWidth="3"
          strokeLinecap="round"
        />

        {bars.map(bar => (
          <g
            key={
              bar.month ||
              bar.label ||
              bar.index
            }
            className="hero-bar-group"
            onMouseEnter={() =>
              setActiveIdx(bar.index)
            }
            onFocus={() =>
              setActiveIdx(bar.index)
            }
            tabIndex={0}
            role="button"
            aria-label={`${getPointLabel(
              bar,
            )}: ${formatMoneyOrDash(
              bar.cost,
            )}`}
          >
            <circle
              className={`hero-bar-dot ${
                activeIdx === bar.index
                  ? 'active'
                  : ''
              } ${
                bar.is_current
                  ? 'current'
                  : ''
              }`}
              cx={bar.cx}
              cy={bar.cy}
              r={
                bar.is_current
                  ? 6
                  : 4
              }
            />

            {activeIdx === bar.index && (
              <line
                className="hero-active-guide"
                x1={bar.cx}
                y1={bar.cy}
                x2={bar.cx}
                y2={CHART_H}
              />
            )}
          </g>
        ))}
      </svg>

      <div className="hero-point-labels">
        {bars.map(bar => (
          <button
            type="button"
            key={
              bar.month ||
              bar.label ||
              bar.index
            }
            className={`hero-point-label mono ${
              activeIdx === bar.index
                ? 'active'
                : ''
            }`}
            onMouseEnter={() =>
              setActiveIdx(bar.index)
            }
            onFocus={() =>
              setActiveIdx(bar.index)
            }
            onClick={() =>
              setActiveIdx(bar.index)
            }
          >
            <span className="hero-point-cost">
              {formatMoneyOrDash(
                bar.cost,
              )}
            </span>

            <span className="hero-point-month">
              {getPointLabel(bar).replace(
                / MTD$/,
                '',
              )}

              {bar.is_partial && (
                <small>MTD</small>
              )}
            </span>
          </button>
        ))}
      </div>

      {activeFilterLabel && (
        <div className="hero-chart-context">
          <span>Filtered view</span>
          <strong>
            {activeFilterLabel}
          </strong>
        </div>
      )}
    </div>
  )
}

export function HeroBottomFigure({
  hero,
}) {
  const total = hero?.total_spend
  const compact = formatCompact(total)

  const useK =
    total != null &&
    Number(total) >= 1000

  return (
    <div className="hero-bottom">
      <div>
        <div className="hero-caption">
          {hero?.total_label ||
            'Collected spend'}
        </div>

        <div className="hero-figure">
          <span className="num">
            {compact}
          </span>

          <span className="unit">
            {useK
              ? 'k · Total cost'
              : ' · Total cost'}
          </span>
        </div>
      </div>

      <div className="hero-bottom-side">
        <span className="hero-caption">
      
        </span>
      </div>
    </div>
  )
}
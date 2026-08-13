import { useEffect, useMemo, useState } from 'react'
import { formatCompact, formatMoneyOrDash } from '../../utils/format'

const CHART_H = 150
const CHART_W = 600

function buildSmoothPath(bars) {
  if (bars.length < 2) return ''
  let d = `M ${bars[0].cx},${bars[0].cy}`
  for (let i = 1; i < bars.length; i += 1) {
    const prev = bars[i - 1]
    const curr = bars[i]
    const cpx = (prev.cx + curr.cx) / 2
    d += ` C ${cpx},${prev.cy} ${cpx},${curr.cy} ${curr.cx},${curr.cy}`
  }
  return d
}

export default function CostHeroChart({ hero, forecast }) {
  const [activeIdx, setActiveIdx] = useState(null)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const t = requestAnimationFrame(() => setMounted(true))
    return () => cancelAnimationFrame(t)
  }, [hero?.trend_points])

  const points = hero?.trend_points || []

  const bars = useMemo(() => {
    if (!points.length) return []
    const maxCost = Math.max(...points.map((p) => p.cost || 0), forecast || 0, 1)
    const barGap = CHART_W / points.length
    const barW = Math.min(28, Math.max(8, barGap * 0.55))

    return points.map((p, i) => {
      const h = Math.max(4, ((p.cost || 0) / maxCost) * (CHART_H - 24))
      const x = i * barGap + (barGap - barW) / 2
      const y = CHART_H - h
      return {
        ...p,
        h,
        x,
        y,
        barW,
        cx: x + barW / 2,
        cy: y,
        index: i,
        delay: `${i * 0.07}s`,
      }
    })
  }, [points, forecast])

  useEffect(() => {
    if (!bars.length) return
    const currentIdx = bars.findIndex((b) => b.is_current)
    setActiveIdx(currentIdx >= 0 ? currentIdx : bars.length - 1)
  }, [bars])

  if (!bars.length) {
    return (
      <div className="hero-chart">
        <div className="chart-empty" style={{ color: 'rgba(255,255,255,.7)' }}>
          No trend data available
        </div>
      </div>
    )
  }

  const linePath = buildSmoothPath(bars)
  const activeBar = activeIdx != null ? bars[activeIdx] : bars[bars.length - 1]

  return (
    <div className="hero-chart">
      {activeBar && (
        <div
          className="hero-badge mono hero-badge-animated"
          style={{ left: `${(activeBar.cx / CHART_W) * 100}%` }}
          key={activeBar.month || activeBar.label}
        >
          {formatMoneyOrDash(activeBar.cost)}
          {activeBar.is_partial && <span className="hero-badge-mtd"> MTD</span>}
        </div>
      )}

      <svg className="hero-svg" viewBox={`0 0 ${CHART_W} ${CHART_H}`} preserveAspectRatio="none">
        <path
          className={`hero-line ${mounted ? 'hero-line-drawn' : ''}`}
          d={linePath}
          fill="none"
          stroke="rgba(255,255,255,.55)"
          strokeWidth="2"
          strokeDasharray="2 7"
          strokeLinecap="round"
        />

        {bars.map((b) => (
          <g
            key={b.month || b.label}
            className="hero-bar-group"
            onMouseEnter={() => setActiveIdx(b.index)}
            onFocus={() => setActiveIdx(b.index)}
            tabIndex={0}
            role="button"
            aria-label={`${b.label || b.month}: ${formatMoneyOrDash(b.cost)}`}
          >
            <rect
              className={`hero-bar-rect ${mounted ? 'hero-bar-rise' : ''} ${b.is_current ? 'current' : ''} ${activeIdx === b.index ? 'active' : ''}`}
              x={b.x}
              y={b.y}
              width={b.barW}
              height={b.h}
              rx={b.is_current ? 4 : 3}
              style={{ animationDelay: b.delay }}
            />
            <circle
              className={`hero-bar-dot ${activeIdx === b.index ? 'active' : ''}`}
              cx={b.cx}
              cy={b.cy}
              r={b.is_current ? 5.5 : 4}
            />
            {activeIdx === b.index && (
              <line
                x1={b.cx}
                y1={b.cy}
                x2={b.cx}
                y2={CHART_H}
                stroke="rgba(255,255,255,.35)"
                strokeWidth="1.5"
                strokeDasharray="3 5"
              />
            )}
          </g>
        ))}
      </svg>

      <div className="hero-point-labels">
        {bars.map((b) => (
          <button
            type="button"
            key={b.month || b.label}
            className={`hero-point-label mono ${activeIdx === b.index ? 'active' : ''} ${b.is_partial ? 'partial' : ''}`}
            onMouseEnter={() => setActiveIdx(b.index)}
            onFocus={() => setActiveIdx(b.index)}
            onClick={() => setActiveIdx(b.index)}
          >
            <span className="hero-point-cost">{formatMoneyOrDash(b.cost)}</span>
            <span className="hero-point-month">
              {(b.label || b.month || '').replace(/ MTD$/, '')}
              {b.is_partial && <span className="hero-mtd-tag">MTD</span>}
            </span>
          </button>
        ))}
      </div>

      {forecast != null && activeBar?.is_current && (
        <div className="hero-forecast-note mono">
          Forecast {formatMoneyOrDash(forecast)}
        </div>
      )}
    </div>
  )
}

export function HeroBottomFigure({ hero }) {
  const total = hero?.total_spend
  const compact = formatCompact(total)
  const useK = total != null && Number(total) >= 1000

  return (
    <div className="hero-bottom">
      <div>
        <div className="hero-caption">{hero?.total_label || 'Collected spend'}</div>
        <div className="hero-figure">
          <span className="num">{compact}</span>
          <span className="unit">{useK ? 'k · Total cost' : ' · Total cost'}</span>
        </div>
      </div>
    </div>
  )
}

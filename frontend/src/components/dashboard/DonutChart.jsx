import { useState } from 'react'

import { formatMoneyOrDash, formatPct } from '../../utils/format'
import { colorForService, OTHER_COLOR } from '../../utils/serviceStyle'

const SIZE = 168
const STROKE = 26
const RADIUS = (SIZE - STROKE) / 2
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

/**
 * Generic hoverable donut + legend. Center label/value swap to the
 * hovered/focused slice's stat, reverting to the total on leave.
 * Backs RegionMixDonut (hover-only glance stat); optional onSelect
 * support is kept for any future click-to-select consumer.
 */
export default function DonutChart({
  rows,
  getLabel,
  getValue,
  maxSlices = 6,
  selectedLabel,
  onSelect,
  emptyMessage = 'No cost data is available yet.',
  ariaLabel = 'Cost mix',
  compact = false,
}) {
  const [hovered, setHovered] = useState(null)

  const sorted = Array.isArray(rows)
    ? rows
        .slice()
        .sort((a, b) => getValue(b) - getValue(a))
    : []

  const total = sorted.reduce(
    (sum, row) => sum + getValue(row),
    0,
  )

  if (!sorted.length || total <= 0) {
    return (
      <div className="snapshot-empty">
        <span>◎</span>
        {emptyMessage}
      </div>
    )
  }

  const top = sorted.slice(0, maxSlices)
  const otherValue = sorted
    .slice(maxSlices)
    .reduce((sum, row) => sum + getValue(row), 0)

  const slices = [
    ...top.map((row) => ({
      name: getLabel(row),
      value: getValue(row),
      color: colorForService(getLabel(row)),
    })),
    ...(otherValue > 0
      ? [{ name: 'Other', value: otherValue, color: OTHER_COLOR }]
      : []),
  ]

  let cumulative = 0

  const arcs = slices.map((slice) => {
    const fraction = slice.value / total
    const dash = fraction * CIRCUMFERENCE
    const offset = cumulative * CIRCUMFERENCE

    cumulative += fraction

    return {
      ...slice,
      fraction,
      dashArray: `${dash} ${CIRCUMFERENCE - dash}`,
      dashOffset: -offset,
    }
  })

  const hoveredArc = hovered
    ? arcs.find((arc) => arc.name === hovered)
    : null

  return (
    <div className={`donut-chart ${compact ? 'donut-chart-compact' : ''}`}>
      <svg
        width={SIZE}
        height={SIZE}
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        role="img"
        aria-label={ariaLabel}
      >
        <g transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}>
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="#edf0f4"
            strokeWidth={STROKE}
          />

          {arcs.map((arc) => (
            <circle
              key={arc.name}
              cx={SIZE / 2}
              cy={SIZE / 2}
              r={RADIUS}
              fill="none"
              stroke={arc.color}
              strokeWidth={STROKE}
              strokeDasharray={arc.dashArray}
              strokeDashoffset={arc.dashOffset}
              className={`donut-arc ${hovered === arc.name ? 'hovered' : ''}`}
              onMouseEnter={() => setHovered(arc.name)}
              onMouseLeave={() => setHovered(null)}
            />
          ))}
        </g>

        <text
          x={SIZE / 2}
          y={SIZE / 2 - 6}
          textAnchor="middle"
          className="donut-center-label"
        >
          {hoveredArc ? hoveredArc.name : 'Total'}
        </text>

        <text
          x={SIZE / 2}
          y={SIZE / 2 + 14}
          textAnchor="middle"
          className="donut-center-value"
        >
          {formatMoneyOrDash(hoveredArc ? hoveredArc.value : total)}
        </text>

        {hoveredArc && (
          <text
            x={SIZE / 2}
            y={SIZE / 2 + 30}
            textAnchor="middle"
            className="donut-center-pct"
          >
            {formatPct(hoveredArc.fraction * 100)}
          </text>
        )}
      </svg>

      <ul className="donut-legend">
        {arcs.map((arc) => (
          <li key={arc.name}>
            <button
              type="button"
              className={
                selectedLabel === arc.name ? 'active' : ''
              }
              onMouseEnter={() => setHovered(arc.name)}
              onMouseLeave={() => setHovered(null)}
              onFocus={() => setHovered(arc.name)}
              onBlur={() => setHovered(null)}
              onClick={() =>
                arc.name !== 'Other' &&
                onSelect?.(
                  selectedLabel === arc.name ? null : arc.name,
                )
              }
              disabled={arc.name === 'Other'}
            >
              <span
                className="donut-legend-dot"
                style={{ background: arc.color }}
              />
              <span className="donut-legend-name">
                {arc.name}
              </span>
              <span className="donut-legend-pct">
                {formatPct(arc.fraction * 100)}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  getCostExplorer,
  getCostExplorerService,
  getCostRegions,
} from '../../api/client'

import {
  formatMoneyOrDash,
  formatPct,
} from '../../utils/format'

import { serviceStyle } from '../../utils/serviceStyle'

const MIN_VISIBLE_COST = 0.01

const DIMENSIONS = [
  {
    value: 'SERVICE',
    label: 'Service',
  },
  {
    value: 'USAGE_TYPE',
    label: 'Usage type',
  },
  {
    value: 'REGION',
    label: 'Region',
  },
]

const DATE_OPTIONS = [
  {
    value: 'current',
    label: 'Current month',
  },
  {
    value: 'previous',
    label: 'Previous month',
  },
  {
    value: 'month',
    label: 'Specific month',
  },
  {
    value: 'three_months',
    label: '3 months ago',
  },
  {
    value: 'six_months',
    label: '6 months ago',
  },
  {
    value: 'custom',
    label: 'Custom range',
  },
]

function safeCost(row) {
  return Number(
    row?.cost ??
      row?.amount ??
      0,
  )
}

function DrillList({
  title,
  rows,
}) {

  return (
    <div className="cost-explorer-drill">

      <div className="cost-explorer-drill-head">
        <span>
          {title}
        </span>
      </div>

      {!rows.length ? (
        <div className="cost-explorer-empty">
          No data available.
        </div>
      ) : (
        <div className="cost-explorer-drill-rows">

          {rows.map(
            row => (
              <div
                className="cost-explorer-drill-row"
                key={row.key}
              >

                <span className="cost-explorer-drill-name">
                  {row.key}
                </span>

                <span className="mono">
                  {formatMoneyOrDash(
                    row.cost,
                  )}
                </span>

                <span className="cost-explorer-drill-share">
                  {formatPct(
                    row.share_pct,
                  )}
                </span>

              </div>
            ),
          )}

        </div>
      )}

    </div>
  )
}

function DetailCard({
  service,
  data,
  onClose,
}) {

  const monthly =
    Array.isArray(
      data?.monthly,
    )
      ? data.monthly
      : []

  const usage =
    Array.isArray(
      data?.usage_types,
    )
      ? data.usage_types
      : []

  const regions =
    Array.isArray(
      data?.regions,
    )
      ? data.regions
      : []

  return (
    <div className="cost-explorer-detail">

      <div className="cost-explorer-detail-head">

        <div className="cost-explorer-detail-title">

          <div className="cost-explorer-detail-avatar">
            {serviceStyle(
              service,
            ).icon}
          </div>

          <div>

            <span className="eyebrow">
              / Service detail
            </span>

            <h3>
              {service}
            </h3>

            <span className="cost-explorer-detail-period">
              {data?.date?.label ||
                'Selected period'}
            </span>

          </div>

        </div>

        <button
          type="button"
          className="small-btn"
          onClick={onClose}
        >
          Close
        </button>

      </div>

      <div className="cost-explorer-detail-total">

        <span>
          Service spend
        </span>

        <strong className="mono">
          {formatMoneyOrDash(
            data?.total_cost,
          )}
        </strong>

      </div>

      <div className="cost-explorer-detail-grid">

        <DrillList
          title="Top usage types"
          rows={usage}
        />

        <DrillList
          title="Regional split"
          rows={regions}
        />

      </div>

      {monthly.length > 1 && (
        <div className="cost-explorer-monthly">

          <div className="cost-explorer-drill-head">
            Monthly service spend
          </div>

          <div className="cost-explorer-monthly-bars">

            {monthly.map(
              item => {

                const value =
                  Number(
                    item.cost ||
                      0,
                  )

                const max =
                  Math.max(
                    ...monthly.map(
                      row =>
                        Number(
                          row.cost ||
                            0,
                        ),
                    ),
                    1,
                  )

                return (
                  <div
                    className="cost-explorer-month"
                    key={item.month}
                  >

                    <div className="cost-explorer-month-bar-wrap">

                      <div
                        className="cost-explorer-month-bar"
                        style={{
                          height: `${Math.max(
                            4,
                            (value /
                              max) *
                              100,
                          )}%`,
                        }}
                      />

                    </div>

                    <span>
                      {item.month.slice(
                        5,
                      )}
                    </span>

                    <strong className="mono">
                      {formatMoneyOrDash(
                        value,
                      )}
                    </strong>

                  </div>
                )
              },
            )}

          </div>

        </div>
      )}

    </div>
  )
}

export default function CostDriversPanel() {

  const [
    dimension,
    setDimension,
  ] = useState(
    'SERVICE',
  )

  const [
    region,
    setRegion,
  ] = useState(
    'all',
  )

  const [
    dateType,
    setDateType,
  ] = useState(
    'current',
  )

  const [
    month,
    setMonth,
  ] = useState(
    '',
  )

  const [
    startDate,
    setStartDate,
  ] = useState(
    '',
  )

  const [
    endDate,
    setEndDate,
  ] = useState(
    '',
  )

  const [
    regions,
    setRegions,
  ] = useState(
    [],
  )

  const [
    explorer,
    setExplorer,
  ] = useState(
    null,
  )

  const [
    selectedService,
    setSelectedService,
  ] = useState(
    null,
  )

  const [
    serviceDetail,
    setServiceDetail,
  ] = useState(
    null,
  )

  const [
    loading,
    setLoading,
  ] = useState(
    false,
  )

  const [
    detailLoading,
    setDetailLoading,
  ] = useState(
    false,
  )

  const [
    error,
    setError,
  ] = useState(
    null,
  )

  const [
    detailError,
    setDetailError,
  ] = useState(
    null,
  )

  useEffect(() => {

    let active = true

    getCostRegions()
      .then(
        data => {

          if (!active) {
            return
          }

          setRegions(
            Array.isArray(
              data?.regions,
            )
              ? data.regions
              : [],
          )
        },
      )
      .catch(
        () => {},
      )

    return () => {
      active = false
    }

  }, [])

  const query = useMemo(
    () => ({
      dimension,
      region:
        region === 'all'
          ? undefined
          : region,
      date_type:
        dateType,
      month:
        dateType === 'month'
          ? month || undefined
          : undefined,
      start_date:
        dateType === 'custom'
          ? startDate || undefined
          : undefined,
      end_date:
        dateType === 'custom'
          ? endDate || undefined
          : undefined,
    }),
    [
      dimension,
      region,
      dateType,
      month,
      startDate,
      endDate,
    ],
  )

  const loadExplorer =
    useCallback(
      async () => {

        if (
          dateType ===
            'month' &&
          !month
        ) {
          return
        }

        if (
          dateType ===
            'custom' &&
          (
            !startDate ||
            !endDate
          )
        ) {
          return
        }

        setLoading(
          true,
        )

        setError(
          null,
        )

        try {

          const data =
            await getCostExplorer(
              query,
            )

          setExplorer(
            data,
          )

        } catch (err) {

          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load cost data.',
          )

        } finally {

          setLoading(
            false,
          )
        }
      },
      [
        query,
        dateType,
        month,
        startDate,
        endDate,
      ],
    )

  useEffect(() => {

    loadExplorer()

  }, [
    loadExplorer,
  ])

  function selectDimension(
    value,
  ) {

    setDimension(
      value,
    )

    setSelectedService(
      null,
    )

    setServiceDetail(
      null,
    )
  }

  async function openService(
    service,
  ) {

    if (
      selectedService ===
      service
    ) {

      setSelectedService(
        null,
      )

      setServiceDetail(
        null,
      )

      return
    }

    setSelectedService(
      service,
    )

    setServiceDetail(
      null,
    )

    setDetailError(
      null,
    )

    setDetailLoading(
      true,
    )

    try {

      const data =
        await getCostExplorerService(
          {
            service,
            region:
              region ===
              'all'
                ? undefined
                : region,
            date_type:
              dateType,
            month:
              dateType ===
              'month'
                ? month ||
                  undefined
                : undefined,
            start_date:
              dateType ===
              'custom'
                ? startDate ||
                  undefined
                : undefined,
            end_date:
              dateType ===
              'custom'
                ? endDate ||
                  undefined
                : undefined,
          },
        )

      setServiceDetail(
        data,
      )

    } catch (err) {

      setDetailError(
        err instanceof Error
          ? err.message
          : 'Unable to load service details.',
      )

    } finally {

      setDetailLoading(
        false,
      )
    }
  }

  const rows =
    Array.isArray(
      explorer?.items,
    )
      ? explorer.items.filter(
          row =>
            safeCost(row) >=
            MIN_VISIBLE_COST,
        )
      : []

  return (
    <section className="panel cost-explorer-panel section-gap">

      <div className="panel-head cost-explorer-head">

        <div>

          <div className="eyebrow">
            / Cost Explorer
          </div>

          <h2 className="panel-title">
            Understand where the spend goes
          </h2>

          <p className="panel-sub">
            Explore AWS spend by dimension without
            changing the live dashboard.
          </p>

        </div>


      </div>

      <div className="cost-explorer-controls">

        <div className="cost-explorer-control">

          <span>
            Region
          </span>

          <select
            value={region}
            onChange={event =>
              setRegion(
                event.target.value,
              )
            }
          >

            <option value="all">
              All regions
            </option>

            {regions.map(
              name => (
                <option
                  key={name}
                  value={name}
                >
                  {name}
                </option>
              ),
            )}

          </select>

        </div>

        <div className="cost-explorer-control">

          <span>
            Date
          </span>

          <select
            value={dateType}
            onChange={event => {
              setDateType(
                event.target.value,
              )
              setSelectedService(
                null,
              )
              setServiceDetail(
                null,
              )
            }}
          >

            {DATE_OPTIONS.map(
              option => (
                <option
                  key={option.value}
                  value={
                    option.value
                  }
                >
                  {option.label}
                </option>
              ),
            )}

          </select>

        </div>

        {dateType ===
          'month' && (
          <div className="cost-explorer-control">

            <span>
              Month
            </span>

            <input
              type="month"
              value={month}
              onChange={event =>
                setMonth(
                  event.target.value,
                )
              }
            />

          </div>
        )}

        {dateType ===
          'custom' && (
          <>
            <div className="cost-explorer-control">

              <span>
                From
              </span>

              <input
                type="date"
                value={startDate}
                max={
                  new Date()
                    .toISOString()
                    .slice(
                      0,
                      10,
                    )
                }
                onChange={event =>
                  setStartDate(
                    event.target.value,
                  )
                }
              />

            </div>

            <div className="cost-explorer-control">

              <span>
                To
              </span>

              <input
                type="date"
                value={endDate}
                max={
                  new Date()
                    .toISOString()
                    .slice(
                      0,
                      10,
                    )
                }
                onChange={event =>
                  setEndDate(
                    event.target.value,
                  )
                }
              />

            </div>
          </>
        )}

      </div>

      <div className="cost-explorer-dimensions">

        <span className="cost-explorer-dimension-label">
          Breakdown
        </span>

        <div className="cost-explorer-segmented">

          {DIMENSIONS.map(
            option => (
              <button
                type="button"
                key={option.value}
                className={
                  dimension ===
                  option.value
                    ? 'active'
                    : ''
                }
                onClick={() =>
                  selectDimension(
                    option.value,
                  )
                }
              >
                {option.label}
              </button>
            ),
          )}

        </div>

        <span className="cost-explorer-scope">
          {explorer?.date?.label ||
            'Current month'}
        </span>

      </div>

      {error && (
        <div className="page-error">
          {error}
        </div>
      )}

      {loading ? (
        <div className="cost-explorer-loading">
          Loading cost data…
        </div>
      ) : selectedService &&
        detailLoading ? (
        <div className="cost-explorer-loading">
          Loading service detail…
        </div>
      ) : selectedService &&
        serviceDetail ? (
        <DetailCard
          service={
            selectedService
          }
          data={
            serviceDetail
          }
          onClose={() => {
            setSelectedService(
              null,
            )
            setServiceDetail(
              null,
            )
          }}
        />
      ) : (
        <>

          {!rows.length ? (
            <div className="cost-explorer-empty-large">
              <strong>
                No cost data available
              </strong>

              <span>
                Cost Explorer returned no
                billable spend for this view.
              </span>
            </div>
          ) : (
            <div className="cost-explorer-list">

              {rows.map(
                (row, index) => {

                  const key =
                    row.key ||
                    row.service ||
                    row.region ||
                    row.usage_type

                  const cost =
                    safeCost(
                      row,
                    )

                  const style =
                    dimension ===
                    'SERVICE'
                      ? serviceStyle(
                          key,
                        )
                      : null

                  return (
                    <div
                      className={`cost-explorer-row ${
                        selectedService ===
                        key
                          ? 'active'
                          : ''
                      }`}
                      key={key}
                    >

                      <button
                        type="button"
                        className="cost-explorer-row-main"
                        onClick={() =>
                          dimension ===
                          'SERVICE'
                            ? openService(
                                key,
                              )
                            : undefined
                        }
                        disabled={
                          dimension !==
                          'SERVICE'
                        }
                      >

                        <span className="cost-explorer-rank mono">
                          {String(
                            index + 1,
                          ).padStart(
                            2,
                            '0',
                          )}
                        </span>

                        {style && (
                          <span
                            className="cost-explorer-avatar"
                            style={{
                              background:
                                style.color,
                            }}
                          >
                            {style.icon}
                          </span>
                        )}

                        <span className="cost-explorer-name">
                          {key}
                        </span>

                        <span className="cost-explorer-share">
                          {formatPct(
                            row.share_pct,
                          )}
                        </span>

                        <span className="cost-explorer-bar-wrap">

                          <span
                            className="cost-explorer-bar"
                            style={{
                              width: `${Math.min(
                                100,
                                Math.max(
                                  0,
                                  Number(
                                    row.share_pct ||
                                      0,
                                  ),
                                ),
                              )}%`,
                            }}
                          />

                        </span>

                        <strong className="mono cost-explorer-cost">
                          {formatMoneyOrDash(
                            cost,
                          )}
                        </strong>

                        {dimension ===
                          'SERVICE' && (
                          <span className="cost-explorer-chevron">
                            →
                          </span>
                        )}

                      </button>

                    </div>
                  )
                },
              )}

            </div>
          )}

        </>
      )}

      {detailError && (
        <div className="page-error">
          {detailError}
        </div>
      )}

    </section>
  )
}
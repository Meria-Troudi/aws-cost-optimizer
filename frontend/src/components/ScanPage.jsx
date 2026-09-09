import { useEffect, useMemo, useState } from 'react'
import { getAccount, getCostRegions } from '../api/client'
import {
  formatDate,
  formatMoneyOrDash,
  pluralize,
} from '../utils/format'
import {
  isDoneStatus,
  isRunningStatus,
} from '../utils/scanStatus'

function formatLocalDate(value) {
  const year = value.getFullYear()
  const month = String(value.getMonth() + 1).padStart(2, '0')
  const day = String(value.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function defaultDates() {
  const end = new Date()
  const start = new Date(end)

  start.setDate(start.getDate() - 90)

  return {
    start_date: formatLocalDate(start),
    end_date: formatLocalDate(end),
  }
}

export default function ScanPage({
  scanData,
  loading,
  status,
  error,
  lastScanTime,
  onRunAnalysis,
  onBack,
  onViewResults,
}) {
  const dates = useMemo(() => defaultDates(), [])

  const [form, setForm] = useState({
    start_date: dates.start_date,
    end_date: dates.end_date,
    region: '',
    cost_threshold: 0,
  })

  const [account, setAccount] = useState(null)
  const [accountLoading, setAccountLoading] = useState(true)
  const [accountError, setAccountError] = useState(null)
  const [availableRegions, setAvailableRegions] = useState([])
  const [regionError, setRegionError] = useState(null)
  const [dateError, setDateError] = useState(null)

  useEffect(() => {
    let mounted = true

    // Account details and the region list come from two different
    // backend calls that can fail independently -- a region-discovery
    // failure affects scan scope (the picker silently falls back to
    // "All regions"), while an account-detail failure is cosmetic. Keep
    // their errors separate so the user can tell which one happened.
    async function loadAccount() {
      try {
        const data = await getAccount()
        if (mounted) {
          setAccount(data)
        }
      } catch (err) {
        if (mounted) {
          setAccountError(
            err instanceof Error
              ? err.message
              : String(err),
          )
        }
      } finally {
        if (mounted) {
          setAccountLoading(false)
        }
      }
    }

    async function loadRegions() {
      try {
        const regionData = await getCostRegions()
        if (mounted) {
          setAvailableRegions(
            Array.isArray(regionData?.regions) ? regionData.regions : [],
          )
        }
      } catch (err) {
        if (mounted) {
          setRegionError(
            err instanceof Error
              ? err.message
              : String(err),
          )
        }
      }
    }

    loadAccount()
    loadRegions()

    return () => {
      mounted = false
    }
  }, [])

  function updateField(name, value) {
    setForm((current) => ({
      ...current,
      [name]: value,
    }))
  }

  async function submit(event) {
    event.preventDefault()

    if (!form.start_date || !form.end_date) {
      setDateError('Select a start and end date.')
      return
    }

    if (form.start_date >= form.end_date) {
      setDateError('Start date must be before end date.')
      return
    }

    setDateError(null)

    await onRunAnalysis(form)
  }

  const isRunning =
    loading ||
    isRunningStatus(status)

  const isDone =
    status === 'done' ||
    isDoneStatus(scanData?.status)

  // The id must be read off the scan itself. Passing the click handler
  // directly (onClick={onViewResults}) hands React's SyntheticEvent to
  // the parent as the scan id, which then requests
  // /api/scans/[object Object].
  const scanId =
    scanData?.id ??
    scanData?.scan_id ??
    null

  // The backend doesn't always report a numeric progress mid-scan --
  // showing a fabricated 50% would read as measured progress rather
  // than "we don't actually know yet", so track whether the value is
  // real separately from the number used to size the fill bar.
  const hasKnownProgress =
    scanData?.progress_percent != null ||
    scanData?.progress != null

  const progress =
    scanData?.progress_percent ??
    scanData?.progress ??
    (isDone ? 100 : 0)

  const safeProgress = Math.min(
    100,
    Math.max(0, Number(progress) || 0),
  )

  const discoveredRegions =
    scanData?.discovered_regions ||
    scanData?.regions ||
    []

  const accountName =
    account?.display_name ||
    account?.account_name ||
    'AWS account'

  return (
    <div className="scan-page">
      <div className="header-row">
        <div className="headline">
          <button
            type="button"
            className="small-btn"
            onClick={onBack}
          >
            ← Back
          </button>

          <h1>
            Cost Analysis
            <br />
          </h1>

          <div className="sub">
            Run an evidence-based AWS cost optimization analysis.
            The scan identifies cost drivers, collects targeted
            resource evidence, and evaluates findings against
            cost conditions.
          </div>
        </div>
      </div>

      {error && (
        <div className="page-error section-gap">
          {error}
        </div>
      )}

      {!error && regionError && (
        <div className="page-error section-gap">
          Could not load the region list, so scope is limited to
          "All regions": {regionError}
        </div>
      )}

      {!error && !regionError && accountError && (
        <div className="page-error section-gap">
          Could not load account details: {accountError}
        </div>
      )}

      <div className="scan-layout">
        <div className="panel scan-form-panel">
          <div className="panel-head">
            <div>
              <div className="panel-title">
                Analysis configuration
              </div>

              <div className="panel-sub">
                Configure the billing period and investigation scope.
              </div>
            </div>
          </div>

          <form onSubmit={submit}>
            <div className="form-grid">
              <div className="form-field">
                <label htmlFor="start_date">
                  Start date
                </label>

                <input
                  id="start_date"
                  type="date"
                  value={form.start_date}
                  onChange={(event) =>
                    updateField(
                      'start_date',
                      event.target.value,
                    )
                  }
                  disabled={isRunning}
                  required
                />
              </div>

              <div className="form-field">
                <label htmlFor="end_date">
                  End date
                </label>

                <input
                  id="end_date"
                  type="date"
                  value={form.end_date}
                  onChange={(event) =>
                    updateField(
                      'end_date',
                      event.target.value,
                    )
                  }
                  disabled={isRunning}
                  required
                />
              </div>

              <div className="form-field">
                <label htmlFor="region">
                  AWS region
                </label>

                <select
                  id="region"
                  value={form.region}
                  onChange={(event) =>
                    updateField(
                      'region',
                      event.target.value,
                    )
                  }
                  disabled={isRunning}
                >
                  <option value="">All regions</option>
                  {availableRegions.map((region) => (
                    <option key={region} value={region}>
                      {region}
                    </option>
                  ))}
                </select>

                <span className="form-help">
                  Select one region or analyze all supported regions.
                </span>
              </div>

              <div className="form-field">
                <label htmlFor="cost_threshold">
                   Minimum spend
                </label>

                <div className="input-with-prefix">
                  <span>$</span>

                  <input
                    id="cost_threshold"
                    type="number"
                    min="0"
                    step="0.01"
                    value={form.cost_threshold}
                    onChange={(event) =>
                      updateField(
                        'cost_threshold',
                        event.target.value,
                      )
                    }
                    disabled={isRunning}
                  />
                </div>

                <span className="form-help">
                  Resources below this spend are deprioritized during analysis.
                </span>
              </div>
            </div>

            {dateError && (
              <div className="form-error">
                {dateError}
              </div>
            )}

            <div className="scan-actions">
              <button
                type="submit"
                className="small-btn primary-btn"
                disabled={isRunning}
              >
                {isRunning ? 'Analyzing…' : 'Start Analysis'}
              </button>
            </div>
          </form>
        </div>

        <div className="panel scan-status-panel">
          <div className="panel-head">
            <div>
              <div className="panel-title">
                Analysis status
              </div>

              <div className="panel-sub">
                Current analysis progress and scope
              </div>
            </div>

            <div
              className={`scan-status-chip ${
                isRunning
                  ? 'running'
                  : isDone
                    ? 'done'
                    : 'idle'
              }`}
            >
              {isRunning
                ? 'Analyzing'
                : isDone
                  ? 'Completed'
                  : 'Ready'}
            </div>
          </div>

          <div className="scan-status-body">
            <div className="scan-status-row">
              <span>Account</span>
              <strong>
                {accountLoading
                  ? 'Loading…'
                  : accountName}
              </strong>
            </div>

            <div className="scan-status-row">
              <span>Analysis window</span>
              <strong>
                {formatDate(form.start_date)}
                {' → '}
                {formatDate(form.end_date)}
              </strong>
            </div>

            <div className="scan-status-row">
              <span>Region</span>
              <strong>
                {form.region || 'All regions'}
              </strong>
            </div>

            <div className="scan-status-row">
              <span>Minimum spend</span>
              <strong>
                {formatMoneyOrDash(form.cost_threshold || 0)}
              </strong>
            </div>

            {lastScanTime &&
              lastScanTime !== '—' && (
                <div className="scan-status-row">
                  <span>Last scan</span>
                  <strong>{lastScanTime}</strong>
                </div>
              )}
          </div>

          {isRunning && (
            <div className="scan-progress">
              <div className="scan-progress-head">
                <span>Analysis in progress</span>
                {hasKnownProgress && (
                  <span>{Math.round(safeProgress)}%</span>
                )}
              </div>

              <div
                className={`scan-progress-track ${
                  hasKnownProgress ? '' : 'indeterminate'
                }`}
              >
                <div
                  className="scan-progress-fill"
                  style={
                    hasKnownProgress
                      ? { width: `${safeProgress}%` }
                      : undefined
                  }
                />
              </div>

              <div className="scan-progress-note">
                  This may take several minutes.
              </div>
            </div>
          )}

          {isDone && scanData && (
            <div className="scan-completed">
              <div className="rec-status">
                <span
                  className="rec-dot"
                  style={{
                    background: 'var(--green)',
                  }}
                />

                <div>
                  <b>
                    Analysis completed
                  </b>

                  <span>
                    {pluralize(
                      scanData.findings_count ?? 0,
                      'finding',
                    )}{' '}
                    ·{' '}
                    {pluralize(
                      scanData.recommendations_count ?? 0,
                      'recommendation',
                    )}
                  </span>
                </div>
              </div>

              <button
                type="button"
                className="small-btn primary-btn"
                onClick={() => onViewResults(scanId)}
              >
                View Results
              </button>
            </div>
          )}

          {discoveredRegions.length > 0 && (
            <div className="scan-regions">
              <div className="panel-sub">
                Regions analyzed
              </div>

              <div className="region-tags">
                {discoveredRegions.map((region) => (
                  <span
                    className="region-tag"
                    key={region}
                  >
                    {region}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

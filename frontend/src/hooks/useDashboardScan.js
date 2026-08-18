import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  getScan,
  startScan,
} from '../api/client'


function formatLocalDate(date) {
  const year = date.getFullYear()
  const month = String(
    date.getMonth() + 1,
  ).padStart(2, '0')
  const day = String(
    date.getDate(),
  ).padStart(2, '0')

  return `${year}-${month}-${day}`
}

function getCurrentMonthDates() {
  const now = new Date()

  return {
    start_date: formatLocalDate(
      new Date(
        now.getFullYear(),
        now.getMonth(),
        1,
      ),
    ),
    end_date: formatLocalDate(now),
  }
}

const POLL_INTERVAL_MS = 3000

const TERMINAL_STATUSES = [
  'completed',
  'completed_with_errors',
  'failed',
  'cancelled',
]

function isTerminal(status) {
  return TERMINAL_STATUSES.includes(
    String(status || '').toLowerCase(),
  )
}

/**
 * Orchestrates a one-click "Scan Current Month" from the dashboard.
 *
 * It uses the exact same backend scan mechanism as the Analysis page,
 * only with precomputed current-month dates. The backend is the single
 * source of truth for status/progress, so the panel survives a tab
 * switch and reflects persistence.
 */
export function useDashboardScan({
  onCompleted,
} = {}) {
  const [scanning, setScanning] =
    useState(false)

  const [scanData, setScanData] =
    useState(null)

  const [error, setError] =
    useState(null)

  const pollRef =
    useRef(null)

  const mountedRef =
    useRef(true)

  const stopPolling =
    useCallback(() => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }, [])

  useEffect(() => {
    mountedRef.current = true

    return () => {
      mountedRef.current = false
      stopPolling()
    }
  }, [stopPolling])

  const pollScan =
    useCallback(
      (scanId) => {
        stopPolling()

        const tick = async () => {
          try {
            const data =
              await getScan(scanId)

            if (!mountedRef.current) {
              return
            }

            setScanData(data)

            const status = String(
              data?.status || '',
            ).toLowerCase()

            if (
              isTerminal(status)
            ) {
              stopPolling()
              setScanning(false)

              if (
                status === 'failed' ||
                status === 'cancelled'
              ) {
                setError(
                  data?.error ||
                    'Scan failed. Check backend logs.',
                )
              } else {
                setError(null)
                onCompleted?.(data)
              }
            }
          } catch (err) {
            if (!mountedRef.current) {
              return
            }

            stopPolling()
            setScanning(false)
            setError(
              err instanceof Error
                ? err.message
                : String(err),
            )
          }
        }

        tick()
        pollRef.current =
          setInterval(
            tick,
            POLL_INTERVAL_MS,
          )
      },
      [onCompleted, stopPolling],
    )

  const scanCurrentMonth =
    useCallback(async () => {
      stopPolling()

      setScanning(true)
      setError(null)
      setScanData(null)

      try {
        const dates =
          getCurrentMonthDates()

        const response =
          await startScan({
            ...dates,
            region: '',
            cost_threshold: 100,
          })

        const scanId =
          response?.scan_id ??
          response?.id ??
          response?.scan?.id

        if (!scanId) {
          throw new Error(
            'Backend started no identifiable scan.',
          )
        }

        setScanData({
          ...(response?.result || {}),
          id: scanId,
          scan_id: scanId,
          status: 'running',
        })

        pollScan(scanId)

        return scanId
      } catch (err) {
        setScanning(false)
        setError(
          err instanceof Error
            ? err.message
            : String(err),
        )
        throw err
      }
    }, [pollScan, stopPolling])

  return {
    scanning,
    scanData,
    error,
    scanCurrentMonth,
    stopPolling,
  }
}

export default useDashboardScan
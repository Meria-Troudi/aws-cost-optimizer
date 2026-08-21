import {
  useCallback,
  useState,
} from 'react'

import {
  startScan,
} from '../api/client'
import { isFailedStatus } from '../utils/scanStatus'
import { usePollScanUntilTerminal } from './usePollScanUntilTerminal'


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

  const { pollUntilTerminal, stopPolling } =
    usePollScanUntilTerminal()

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
            cost_threshold: 0,
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

        const data = await pollUntilTerminal(
          scanId,
          {
            onTick: (tickData, meta) => {
              if (tickData) {
                setScanData(tickData)
              }

              if (meta?.warning) {
                setError(meta.warning)
              }
            },
          },
        )

        setScanning(false)

        if (
          isFailedStatus(
            data?.status,
          )
        ) {
          setError(
            data?.error ||
              'Scan failed. Check backend logs.',
          )
        } else {
          setError(null)
          onCompleted?.(data)
        }

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
    }, [onCompleted, pollUntilTerminal, stopPolling])

  return {
    scanning,
    scanData,
    error,
    scanCurrentMonth,
    stopPolling,
  }
}

export default useDashboardScan

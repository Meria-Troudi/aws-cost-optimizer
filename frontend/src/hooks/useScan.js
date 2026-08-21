import { useCallback, useState } from 'react'

import { startScan } from '../api/client'
import { isFailedStatus } from '../utils/scanStatus'
import { usePollScanUntilTerminal } from './usePollScanUntilTerminal'

export function useScan() {
  const [scanData, setScanData] =
    useState(null)

  const [loading, setLoading] =
    useState(false)

  const [status, setStatus] =
    useState('idle')

  const [error, setError] =
    useState(null)

  const [lastScanTime, setLastScanTime] =
    useState('—')

  const { pollUntilTerminal, stopPolling } =
    usePollScanUntilTerminal()

  const runScan =
    useCallback(
      async (form) => {
        stopPolling()

        setError(null)

        setScanData(null)

        setLoading(true)

        setStatus('running')

        try {
          const payload = {
            start_date:
              form.start_date,

            end_date:
              form.end_date,

            region:
              form.region || null,

            cost_threshold:
              Number(
                form.cost_threshold,
              ),
          }

          const response =
            await startScan(payload)

          const scanId =
            response?.scan_id ??
            response?.id ??
            response?.scan?.id

          if (!scanId) {
            throw new Error(
              'Backend started no identifiable scan. Expected scan_id in the response.',
            )
          }

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

          setLoading(false)

          setLastScanTime(
            new Date().toLocaleString(
              'en-GB',
            ),
          )

          if (
            isFailedStatus(
              data?.status,
            )
          ) {
            setStatus('idle')

            const message =
              data?.error ||
              data?.error_message ||
              'Analysis failed. Check backend logs.'

            setError(message)

            throw new Error(message)
          }

          setStatus('done')

          setError(null)

          return scanId
        } catch (err) {
          stopPolling()

          setLoading(false)

          setStatus('idle')

          const message =
            err instanceof Error
              ? err.message
              : String(err)

          setError(message)

          throw err
        }
      },
      [pollUntilTerminal, stopPolling],
    )

  return {
    scanData,

    loading,

    status,

    error,

    lastScanTime,

    runScan,

    stopPolling,
  }
}

export default useScan

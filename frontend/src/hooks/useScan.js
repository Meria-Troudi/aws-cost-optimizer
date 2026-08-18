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

const POLL_INTERVAL_MS = 3000
const MAX_POLLS = 600

function isTerminalStatus(status) {
  return [
    'completed',
    'completed_with_errors',
    'failed',
    'cancelled',
  ].includes(
    String(status || '').toLowerCase(),
  )
}

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

  const pollRef =
    useRef(null)

  const mountedRef =
    useRef(true)

  useEffect(() => {
    mountedRef.current = true

    return () => {
      mountedRef.current = false

      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [])

  const stopPolling =
    useCallback(() => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }, [])

  const pollScan =
    useCallback(
      (scanId) =>
        new Promise((resolve, reject) => {
          let attempts = 0
          let finished = false

          const finish = (callback, value) => {
            if (finished) return

            finished = true

            stopPolling()

            callback(value)
          }

          const poll = async () => {
            attempts += 1

            try {
              const data =
                await getScan(scanId)

              if (!mountedRef.current) {
                finish(resolve, scanId)
                return
              }

              setScanData(data)

              const currentStatus =
                String(
                  data?.status || '',
                ).toLowerCase()

              if (
                isTerminalStatus(
                  currentStatus,
                )
              ) {
                setLoading(false)

                setLastScanTime(
                  new Date().toLocaleString(
                    'en-GB',
                  ),
                )

                if (
                  currentStatus ===
                    'failed' ||
                  currentStatus ===
                    'cancelled'
                ) {
                  setStatus('idle')

                  const message =
                    data?.error ||
                    data?.error_message ||
                    'Analysis failed. Check backend logs.'

                  setError(message)

                  finish(
                    reject,
                    new Error(message),
                  )

                  return
                }

                setStatus('done')

                setError(null)

                finish(
                  resolve,
                  scanId,
                )

                return
              }

              if (
                attempts >= MAX_POLLS
              ) {
                setLoading(false)

                setStatus('idle')

                const message =
                  'Analysis is taking longer than expected. Check the scan status or backend logs.'

                setError(message)

                finish(
                  reject,
                  new Error(message),
                )
              }
            } catch (err) {
              setLoading(false)

              setStatus('idle')

              const message =
                err instanceof Error
                  ? err.message
                  : String(err)

              setError(message)

              finish(
                reject,
                err,
              )
            }
          }

          poll()

          pollRef.current =
            setInterval(
              poll,
              POLL_INTERVAL_MS,
            )
        }),
      [stopPolling],
    )

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

          return await pollScan(
            scanId,
          )
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
      [pollScan, stopPolling],
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
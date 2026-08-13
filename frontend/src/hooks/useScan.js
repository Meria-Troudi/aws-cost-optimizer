import { useCallback, useRef, useState } from 'react'
import { getScan, startScan } from '../api/client'

const POLL_INTERVAL_MS = 3000
const MAX_POLLS = 600

function isTerminalStatus(data) {
  return (
    data.status === 'completed' ||
    data.status === 'completed_with_errors' ||
    data.status === 'failed'
  )
}

export function useScan() {
  const [scanData, setScanData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState(null)
  const [lastScanTime, setLastScanTime] = useState('—')
  const pollRef = useRef(null)

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const pollScan = useCallback(
    (scanId) =>
      new Promise((resolve, reject) => {
        let attempts = 0

        const poll = async () => {
          attempts += 1
          try {
            const data = await getScan(scanId)
            setScanData(data)

            if (isTerminalStatus(data)) {
              stopPolling()
              setLoading(false)
              setLastScanTime(new Date().toLocaleString('en-GB'))

              if (data.status === 'failed') {
                setStatus('idle')
                const msg = 'Analysis failed — check backend logs.'
                setError(msg)
                reject(new Error(msg))
                return
              }

              setStatus('done')
              setError(null)
              resolve(scanId)
              return
            }

            if (attempts >= MAX_POLLS) {
              stopPolling()
              setLoading(false)
              setStatus('idle')
              const msg =
                'Analysis is taking longer than expected. Check backend logs, or restart the API without --reload.'
              setError(msg)
              reject(new Error(msg))
            }
          } catch (err) {
            stopPolling()
            setLoading(false)
            setStatus('idle')
            setError(err.message)
            reject(err)
          }
        }

        poll()
        pollRef.current = setInterval(poll, POLL_INTERVAL_MS)
      }),
    [stopPolling],
  )

  const runScan = useCallback(
    async (form) => {
      setError(null)
      setLoading(true)
      setStatus('running')
      stopPolling()

      const { scan_id } = await startScan({
        start_date: form.start_date,
        end_date: form.end_date,
        region: form.region,
        cost_threshold: Number(form.cost_threshold),
      })

      return pollScan(scan_id)
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

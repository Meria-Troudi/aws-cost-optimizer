import { useCallback, useEffect, useRef } from 'react'

import { getScan } from '../api/client'
import { isTerminalStatus } from '../utils/scanStatus'

const POLL_INTERVAL_MS = 3000
const MAX_POLLS = 600

// Consecutive failed status checks tolerated before giving up. The scan
// runs server-side, so a dropped request or a backend restart must not
// be reported to the user as a failed scan.
const MAX_CONSECUTIVE_POLL_ERRORS = 5

/**
 * Poll a scan's status until it reaches a terminal state, tolerating a
 * bounded run of consecutive network/API errors (the scan keeps running
 * server-side regardless of whether the client can currently reach it).
 *
 * `onTick(data)` fires on every successful poll (terminal or not) so the
 * caller can keep its own scan-data state in sync.
 *
 * Resolves with the final scan data on success (including a "failed" or
 * "cancelled" terminal status -- the caller decides what that means),
 * or rejects if polling is given up on (max attempts or max consecutive
 * errors reached).
 */
export function usePollScanUntilTerminal() {
  const pollRef = useRef(null)
  const mountedRef = useRef(true)

  const stopPolling = useCallback(() => {
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

  const pollUntilTerminal = useCallback(
    (scanId, { onTick } = {}) =>
      new Promise((resolve, reject) => {
        stopPolling()

        let attempts = 0
        let consecutiveErrors = 0
        let finished = false

        const finish = (callback, value) => {
          if (finished) return

          finished = true

          stopPolling()

          callback(value)
        }

        const tick = async () => {
          attempts += 1

          try {
            const data = await getScan(scanId)

            if (!mountedRef.current) {
              finish(resolve, data)
              return
            }

            // A poll succeeded, so any earlier blip was transient.
            consecutiveErrors = 0

            onTick?.(data)

            const status = data?.status

            if (isTerminalStatus(status)) {
              finish(resolve, data)
              return
            }

            if (attempts >= MAX_POLLS) {
              finish(
                reject,
                new Error(
                  'Analysis is taking longer than expected. Check the scan status or backend logs.',
                ),
              )
            }
          } catch (err) {
            if (!mountedRef.current) {
              finish(resolve, null)
              return
            }

            consecutiveErrors += 1

            const message =
              err instanceof Error
                ? err.message
                : String(err)

            // The scan runs server-side and keeps going regardless of
            // whether we can reach the API. Giving up on the first
            // dropped request or backend restart reported a healthy
            // scan as failed, so tolerate a short outage.
            if (consecutiveErrors < MAX_CONSECUTIVE_POLL_ERRORS) {
              onTick?.(null, {
                warning: `Lost contact with the backend (attempt ${consecutiveErrors} of ${MAX_CONSECUTIVE_POLL_ERRORS}). Retrying — the scan is still running.`,
              })

              return
            }

            finish(
              reject,
              new Error(
                `${message} — gave up after ${consecutiveErrors} consecutive failed status checks. The scan may still be running; reopen it from the results page.`,
              ),
            )
          }
        }

        tick()

        pollRef.current = setInterval(
          tick,
          POLL_INTERVAL_MS,
        )
      }),
    [stopPolling],
  )

  return {
    pollUntilTerminal,
    stopPolling,
    mountedRef,
  }
}

export default usePollScanUntilTerminal

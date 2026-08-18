import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  getDashboard,
} from '../api/client'

export function useDashboard() {
  const [dashboardData, setDashboardData] =
    useState(null)

  const [loading, setLoading] =
    useState(false)

  const [refreshing, setRefreshing] =
    useState(false)

  const [error, setError] =
    useState(null)

  const autoRefreshAttempted =
    useRef(false)

  const loadDashboard =
    useCallback(async (filterParams = {}) => {
      setLoading(true)
      setError(null)

      try {
        const data = await getDashboard(filterParams)

        setDashboardData(data)
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : String(err)
        )
      } finally {
        setLoading(false)
      }
    }, [])

  const refreshCosts =
    useCallback(async (filterParams = {}) => {
      setRefreshing(true)
      setError(null)

      try {
        // The dashboard reads current Cost Explorer data directly; there is
        // no separate local cache to refresh before loading it again.
        await loadDashboard(filterParams)
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : String(err)
        )
      } finally {
        setRefreshing(false)
      }
    }, [loadDashboard])

  useEffect(() => {
    loadDashboard({ history_months: 6 })
  }, [loadDashboard])

  /*
   * If the dashboard has no cost data,
   * attempt one backend refresh.
   */
  useEffect(() => {
    if (autoRefreshAttempted.current) {
      return
    }

    if (loading || refreshing) {
      return
    }

    if (dashboardData?.cost_available) {
      return
    }

    autoRefreshAttempted.current = true

    refreshCosts({ history_months: 6 })
  }, [
    loading,
    refreshing,
    dashboardData?.cost_available,
    refreshCosts,
  ])

  return {
    dashboardData,
    loading,
    refreshing,
    error,
    loadDashboard,
    refreshCosts,
  }
}

export default useDashboard

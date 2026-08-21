import {
  useCallback,
  useEffect,
  useState,
} from 'react'

import {
  getDashboard,
} from '../api/client'


export function useDashboard() {

  const [
    dashboardData,
    setDashboardData,
  ] = useState(null)

  const [
    loading,
    setLoading,
  ] = useState(false)

  const [
    refreshing,
    setRefreshing,
  ] = useState(false)

  const [
    error,
    setError,
  ] = useState(null)


  const loadDashboard =
    useCallback(
      async (
        params = {},
      ) => {

        setLoading(
          true,
        )

        setError(
          null,
        )

        try {

          const data =
            await getDashboard(
              {
                history_months: 6,
                ...params,
              },
            )

          setDashboardData(
            data,
          )

        } catch (err) {

          setError(
            err instanceof Error
              ? err.message
              : String(err),
          )

        } finally {

          setLoading(
            false,
          )
        }
      },
      [],
    )


  const refreshCosts =
    useCallback(
      async (
        params = {},
      ) => {

        setRefreshing(
          true,
        )

        setError(
          null,
        )

        try {

          const data =
            await getDashboard(
              {
                history_months: 6,
                force_refresh: true,
                ...params,
              },
            )

          setDashboardData(
            data,
          )

        } catch (err) {

          setError(
            err instanceof Error
              ? err.message
              : String(err),
          )

        } finally {

          setRefreshing(
            false,
          )
        }
      },
      [],
    )


  useEffect(() => {

    loadDashboard({
      history_months: 6,
    })

  }, [
    loadDashboard,
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
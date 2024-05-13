import { type FC, Suspense, useMemo } from 'react'
import { Route, Routes } from 'react-router-dom'

import { Helmet } from 'components'

import routesList from './routes'

export const RoutesWrapper: FC = () => {
  const renderRoutes = useMemo(
    () =>
      routesList.map(({ element: Element, path, title }) => (
        <Route
          key={path}
          path={path}
          element={
            <Suspense>
              <Helmet key={title} title={title}>
                <Element />
              </Helmet>
            </Suspense>
          }
        />
      )),

    []
  )

  return <Routes>{renderRoutes}</Routes>
}

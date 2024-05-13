import { lazy } from 'react'

import { ERoutePaths, type TRoutePageType } from './types'

const SignIn = lazy(() => import('pages/SignIn'))
const SignUp = lazy(() => import('pages/SignUp'))
const Error = lazy(() => import('pages/Error'))
const Home = lazy(() => import('pages/Home'))

const routesList: TRoutePageType[] = [
  {
    element: Home,
    path: ERoutePaths.Home,
    title: 'Home',
  },
  {
    element: SignIn,
    path: ERoutePaths.SignIn,
    title: 'Sign in',
  },
  {
    element: SignUp,
    path: ERoutePaths.SignUp,
    title: 'Sign up',
  },
  {
    element: Error,
    path: ERoutePaths.Error,
    title: 'Error',
  },
]

export default routesList

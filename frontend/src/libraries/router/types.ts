import type { FC } from 'react'

export type TRoutePageType = {
  element: FC
  path: string
  title: string
}

export enum ERoutePaths {
  SignIn = '/',
  Home = '/home',
  SignUp = '/sign-up',

  Error = '*',
}

import type { FC, SVGProps } from 'react'
import type { Action, ThunkAction } from '@reduxjs/toolkit'

import { store } from 'libraries/redux'

export type TSVG = FC<SVGProps<SVGSVGElement>>

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch
export type AppThunk = ThunkAction<void, RootState, null, Action<string>>

export enum EFetchingStatus {
  IDLE = 'IDLE',
  PENDING = 'PENDING',
  REJECTED = 'REJECTED',
  FULFILLED = 'FULFILLED',
}

export interface RequestState {
  error: any
  loading: boolean
}

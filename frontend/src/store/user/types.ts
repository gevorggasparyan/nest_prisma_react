import type { RequestState } from 'types'
import type { TSignUpReq } from 'store/auth/types'

export interface IUserDataState extends RequestState {
  user?: TSignUpReq | null
}

export type TUserState = {
  data: IUserDataState
}

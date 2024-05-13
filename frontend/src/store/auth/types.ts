import type { RequestState } from 'types'

export type TSignInReq = {
  username: string
  password: string
}

export type TSignUpReq = {
  email: string
  password: string
  username: string
}

export interface SignUpState extends RequestState {
  data: TSignUpReq | null
}

export interface SignInState extends RequestState {
  data: {
    accessToken: string
  } | null
}

export type IAuthInitialState = {
  signIn: SignInState
  signUp: SignUpState
}

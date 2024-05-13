import type { RootState } from 'types'

const getSignIn = (state: RootState) => state.auth.signIn

const getSignUp = (state: RootState) => state.auth.signUp

export const AuthSelectors = {
  getSignIn,
  getSignUp,
}

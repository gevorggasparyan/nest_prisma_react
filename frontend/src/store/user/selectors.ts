import type { RootState } from 'types'

const getProfile = (state: RootState) => state.user.data

export const UserSelectors = {
  getProfile,
}

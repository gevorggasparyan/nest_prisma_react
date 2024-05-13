import type { ReactNode, MouseEvent, KeyboardEvent } from 'react'

export default interface IButton {
  className?: string
  disabled?: boolean
  ariaLabel?: string
  isLoading?: boolean
  isFillIgnore?: boolean
  children?: ReactNode | string
  type?: 'submit' | 'reset' | 'button'
  onClick?: (event: MouseEvent<HTMLButtonElement>) => void
  onKeyDownHandler?: (event: KeyboardEvent<HTMLVideoElement>) => void
}

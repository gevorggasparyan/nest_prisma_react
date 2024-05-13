import type { ChangeEvent, FocusEvent, HTMLInputTypeAttribute, KeyboardEvent } from 'react'

import type { TSVG } from 'types'

export type TInput = {
  name: string
  Icon?: TSVG
  register?: any
  label?: string
  maxLength?: number
  minLength?: number
  disabled?: boolean
  className?: string
  placeholder?: string
  error?: string | any
  autoComplete?: string
  value?: string | number
  containerClass?: string
  type?: HTMLInputTypeAttribute
  onBlur?: (data: FocusEvent<HTMLInputElement>) => void
  onFocus?: (data: FocusEvent<HTMLInputElement>) => void
  onKeyDown?: (data: KeyboardEvent<HTMLInputElement>) => void
  onChange?: (value: string | number, event: ChangeEvent<HTMLInputElement>) => void
}

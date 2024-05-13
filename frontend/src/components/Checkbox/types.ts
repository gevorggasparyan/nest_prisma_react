import type { ChangeEvent, ReactNode } from 'react'

export type TCheckboxProps = {
  name?: string
  register?: any
  checked?: boolean
  disabled?: boolean
  topMargin?: boolean
  className?: string
  labelClassName?: string
  checkboxClassName?: string
  label?: string | ReactNode
  onChange?: (value: boolean, e: ChangeEvent<HTMLInputElement>) => void
}

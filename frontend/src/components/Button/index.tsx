import type { FC } from 'react'
import { noop } from 'lodash'
import classNames from 'classnames'

import { Loader } from 'components'

import type IButton from './types'
import styles from './Button.module.scss'

const Button: FC<IButton> = ({
  onClick,
  disabled,
  children,
  isLoading,
  ariaLabel = '',
  className = '',
  type = 'button',
  onKeyDownHandler = noop,
}) => {
  const allClassNames = classNames(styles.button, className, {
    [styles.loading]: isLoading,
  })

  return (
    <button
      type={type}
      onClick={onClick}
      aria-label={ariaLabel}
      data-testid='button'
      className={allClassNames}
      onKeyDown={onKeyDownHandler}
      disabled={isLoading || disabled}
    >
      {isLoading && <Loader />}
      {children}
    </button>
  )
}

export default Button

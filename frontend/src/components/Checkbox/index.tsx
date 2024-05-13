import type { FC, ChangeEvent } from 'react'
import classNames from 'classnames'

import type { TCheckboxProps } from './types'
import styles from './Checkbox.module.scss'

const Checkbox: FC<TCheckboxProps> = ({
  name,
  label,
  checked,
  onChange,
  register,
  className,
  disabled,
  topMargin,
  labelClassName,
  checkboxClassName,
}) => {
  const labelPosition = classNames(labelClassName, {
    [styles.right_start]: topMargin,
  })

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    onChange!(event.target.checked, event)
  }

  return (
    <div className={classNames(styles.wrapper, className)} data-testid='checkbox-wrapper'>
      {label ? (
        <label
          className={classNames(styles.wrapper__label, labelPosition, { [styles.wrapper__label__checked]: checked })}
          data-testid='checkbox-label'
        >
          <input
            data-testid='checkbox-input'
            type='checkbox'
            checked={checked}
            disabled={disabled}
            onChange={handleChange}
            className={classNames(checkboxClassName, { [styles.checkbox]: topMargin })}
            {...(register ? register(name) : null)}
          />
          {label}
        </label>
      ) : (
        <input
          data-testid='checkbox-input'
          type='checkbox'
          checked={checked}
          disabled={disabled}
          onChange={handleChange}
          {...(register ? register(name) : null)}
        />
      )}
    </div>
  )
}

export default Checkbox

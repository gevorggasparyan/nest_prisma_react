import { forwardRef, useState, type FocusEvent, type ChangeEvent, type LegacyRef, type KeyboardEvent } from 'react'
import classNames from 'classnames'

import { ErrorIcon, HideIcon, ShowIcon } from 'assets'

import type { TInput } from './types'
import styles from './Input.module.scss'

const Input = forwardRef(
  (
    {
      name,
      Icon,
      error,
      label,
      value,
      onBlur,
      onFocus,
      register,
      disabled,
      onChange,
      maxLength,
      minLength,
      onKeyDown,
      className = '',
      placeholder = '',
      containerClass = '',
      autoComplete = 'off',
      type = 'text',
    }: TInput,
    ref: LegacyRef<HTMLInputElement>
  ) => {
    const [isOpen, setIsOpen] = useState<boolean>(false)

    const isPassword = type === 'password'
    const inputClassName = classNames(className, styles.wrapper__input, {
      [styles.wrapper__input__error]: error,
      [styles.wrapper__input__icon]: Icon,
    })

    const eyeIconToggler = () => {
      setIsOpen(!isOpen)
    }

    const onChangeValueHandler = (e: ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value
      onChange?.(value, e)
    }

    const onBlurHandler = (e: FocusEvent<HTMLInputElement>) => {
      onBlur?.(e)
    }

    const onFocusHandler = (e: FocusEvent<HTMLInputElement>) => {
      onFocus?.(e)
    }

    const onKeyDownHandler = (e: KeyboardEvent<HTMLInputElement>) => {
      onKeyDown?.(e)
    }

    const onRegisterChangeCallback = {
      onChange: onChangeValueHandler,
      onBlur: onBlurHandler,
    }

    return (
      <div
        data-testid='input-wrapper'
        className={classNames(styles.wrapper, {
          [containerClass]: containerClass,
        })}
      >
        {(label || error) && (
          <div className={styles.wrapper__head}>
            {label && (
              <p data-testid='input-label' className={styles.wrapper__label}>
                {label}
              </p>
            )}
            {error && (
              <div className={styles.wrapper_error_part}>
                <ErrorIcon className={styles.wrapper_error_part_icon} />
                <p className={styles.wrapper_error_part_text}>{error}</p>
              </div>
            )}
          </div>
        )}

        <div className={styles.wrapper__box}>
          {Icon ? <Icon data-testid='input-icon' className={styles.wrapper__icon} /> : null}

          <input
            data-testid='input'
            ref={ref}
            name={name}
            value={value}
            disabled={disabled}
            maxLength={maxLength}
            minLength={minLength}
            onFocus={onFocusHandler}
            placeholder={placeholder}
            className={inputClassName}
            autoComplete={autoComplete}
            onKeyDown={onKeyDownHandler}
            type={isOpen ? 'text' : type}
            onChange={onChangeValueHandler}
            onBlur={onBlurHandler}
            {...(register ? register(name, onRegisterChangeCallback) : null)}
          />

          {isPassword && (
            <div className={styles.wrapper__box__container}>
              <div
                data-testid='input-password'
                onClick={eyeIconToggler}
                className={classNames(styles.wrapper__box__eye, { [styles.wrapper__box__eye__open]: isOpen })}
              >
                {!isOpen ? <HideIcon /> : <ShowIcon />}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }
)

export default Input

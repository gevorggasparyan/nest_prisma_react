import type { FC } from 'react'
import { useNavigate } from 'react-router-dom'

import { Button } from 'components'
import { getCookie } from 'libraries/cookie'
import { ERoutePaths } from 'libraries/router/types'

import styles from './Error.module.scss'

const Error: FC = () => {
  const isAuth = getCookie('token')
  const navigate = useNavigate()

  const changeToRealRouteHandler = () => {
    navigate(`${isAuth ? ERoutePaths.Home : ERoutePaths.SignIn}`)
  }

  return (
    <div className={styles.wrapper}>
      <h1 className={styles.wrapper__title}>You don't have this route</h1>

      <Button className={styles.wrapper__button} onClick={changeToRealRouteHandler}>
        Go to real route
      </Button>
    </div>
  )
}

export default Error

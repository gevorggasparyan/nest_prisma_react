import type { FC } from 'react'

import { Button } from 'components'
import { useNavigate } from 'react-router-dom'
import { removeCookie } from 'libraries/cookie'
import { useAppSelector } from 'libraries/redux'
import { ERoutePaths } from 'libraries/router/types'

import { UserSelectors } from 'store/user/selectors'
import styles from './Header.module.scss'

const Header: FC = () => {
  const navigate = useNavigate()
  const { user } = useAppSelector(UserSelectors.getProfile)

  const logOutHandler = () => {
    removeCookie('token')
    navigate(ERoutePaths.SignIn)
  }

  return (
    <header className={styles.header}>
      <div className={styles.header__user}>
        <img
          width={40}
          height={40}
          className={styles.header__user_img}
          src='https://cdn-icons-png.flaticon.com/512/9131/9131529.png'
        />

        <div className={styles.header__user__info}>
          <p className={styles.header__user__info_name}>{user?.username}</p>
          <p className={styles.header__user__info_email}>{user?.email}</p>
        </div>
      </div>

      <Button onClick={logOutHandler} className={styles.header__log_out}>
        Log out
      </Button>
    </header>
  )
}

export default Header

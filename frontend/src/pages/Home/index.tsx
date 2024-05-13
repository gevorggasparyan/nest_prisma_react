import { Fragment, useEffect, type FC } from 'react'

import { Header, ToDo } from 'components'
import { getTasks } from 'store/tasks/actions'
import { useAppDispatch } from 'libraries/redux'
import { getProfileData } from 'store/user/actions'

import styles from './Home.module.scss'

const Home: FC = () => {
  const dispatch = useAppDispatch()

  useEffect(() => {
    dispatch(getTasks())
    dispatch(getProfileData())
  })

  return (
    <Fragment>
      <Header />

      <section className={styles.container}>
        <div className={styles.container__wrapper}>
          <ToDo />
        </div>
      </section>
    </Fragment>
  )
}

export default Home

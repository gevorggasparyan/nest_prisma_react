import type { FC } from 'react'

import { RoutesWrapper } from 'libraries/router'

import styles from './PageLayout.module.scss'

const PageLayout: FC = () => (
  <main className={styles.wrapper}>
    <section className={styles.wrapper__content}>
      <RoutesWrapper />
    </section>
  </main>
)

export default PageLayout

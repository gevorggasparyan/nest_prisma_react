import { FC } from 'react'
import classNames from 'classnames'

import type { TLoader } from './types'

import styles from './Loader.module.scss'

const emptyArray: string[] = new Array(4).fill('')

const Loader: FC<TLoader> = ({ className }) => {
  const renderEmptyBlocks = emptyArray.map((_, idx) => <div key={idx} data-testid='empty-blocks' />)

  return (
    <div className={classNames(styles.wrapper, className)} data-testid='loader'>
      {renderEmptyBlocks}
    </div>
  )
}

export default Loader

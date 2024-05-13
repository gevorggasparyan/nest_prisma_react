import { toast } from 'react-toastify'
import { injectStyle } from 'react-toastify/dist/inject-style'

import { ErrorIcon, InfoIcon, TickPrimaryIcon, WarningIcon } from 'assets'

import ToastTexts from './ToastTexts'
import { ToastVersions } from './types'
import styles from './Toast.module.scss'

export { ToastVersions }

export const showNotification = (type: ToastVersions, title: string, description?: string) => {
  injectStyle()

  const toastContent = (color: string) => <ToastTexts color={color} title={title} description={description} />

  switch (type) {
    case ToastVersions.success:
      toast(toastContent('#47CB92'), {
        type: ToastVersions.success,
        icon: <TickPrimaryIcon className={styles.success} />,
      })
      break

    case ToastVersions.error:
      toast(toastContent('#F27D7D'), {
        type: ToastVersions.error,
        icon: <ErrorIcon className={styles.error} />,
      })
      break

    case ToastVersions.warning:
      toast(toastContent('#F0B774'), {
        type: ToastVersions.warning,
        icon: <WarningIcon className={styles.warning} />,
      })
      break

    case ToastVersions.info:
      toast(toastContent('#5C90DD'), {
        type: ToastVersions.info,
        icon: <InfoIcon className={styles.info} />,
      })
      break

    default:
      break
  }
}

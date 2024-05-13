export enum ToastVersions {
  info = 'info',
  error = 'error',
  success = 'success',
  warning = 'warning',
}

export type TToastNotificationProps = {
  type?: ToastVersions
  title: string
  description?: string
}

export type TToastTextsProps = {
  color: string
  title: string
  description?: string
}

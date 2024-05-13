import type { TTasks } from 'store/tasks/types'

export type TItemChangeSubmit = {
  task: string
}

export type TSubmit = {
  title: string
}

export type TToDoItemProps = {
  data: TTasks
  deleteTask: (e: number) => void
  editTask: (e: string, id: number) => void
  changeTaskStatus: (e: boolean, id: number) => void
}

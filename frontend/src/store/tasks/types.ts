import type { RequestState } from 'types'

export type TSendTasks = {
  title: string
  completed: boolean
}

export interface IUserDataState extends RequestState {
  user?: any
}

export type TTasks = {
  id: number
  title: string
  userId: number
  createdAt: string
  completed: boolean
  description: string
}

export interface IUserToDoList extends RequestState {
  data: {
    tasks: TTasks[]
    totalTasksCount: number
  } | null
}

export type TUserState = {
  todoList: IUserToDoList
}

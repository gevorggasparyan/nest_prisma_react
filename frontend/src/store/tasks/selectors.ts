import type { RootState } from 'types'

const getTodoList = (state: RootState) => state.tasks.todoList

export const TaskSelectors = {
  getTodoList,
}

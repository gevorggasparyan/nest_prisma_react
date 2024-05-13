import { Fragment, type FC } from 'react'
import { useForm } from 'react-hook-form'

import { TTasks } from 'store/tasks/types'
import { Button, Input, Loader } from 'components'
import { TaskSelectors } from 'store/tasks/selectors'
import { useAppDispatch, useAppSelector } from 'libraries/redux'
import { deleteTasks, editTasks, sendTasks } from 'store/tasks/actions'

import ToDoItem from './ToDoItem'
import type { TSubmit } from './types'
import styles from './ToDo.module.scss'

const ToDo: FC = () => {
  const dispatch = useAppDispatch()

  const { data, loading } = useAppSelector(TaskSelectors.getTodoList)
  const { tasks, totalTasksCount } = data || { tasks: [], totalTasksCount: 0 }

  const { register, handleSubmit, reset } = useForm<any>({
    mode: 'onChange',
  })

  const onSubmit = (data: TSubmit) => {
    const { title } = data
    const formatData = {
      completed: false,
      title,
    }

    dispatch(sendTasks(formatData))
    reset()
  }

  const changeTaskStatus = (value: boolean, id: number) => {
    const activeTask = tasks?.find((task: TTasks) => task.id === id)
    const editedTask = {
      ...activeTask,
      completed: value,
    }

    dispatch(editTasks({ id, editedTask }))
  }

  const deleteTask = (id: number) => {
    dispatch(deleteTasks(id))
  }

  const editTask = (editedTaskValue: string, id: number) => {
    const activeTask = tasks?.find((task: TTasks) => task.id === id)
    const editedTask = {
      ...activeTask,
      title: editedTaskValue,
    }

    dispatch(editTasks({ id, editedTask }))
  }

  const renderTasks = tasks?.map((todo: TTasks) => (
    <ToDoItem
      key={todo.id}
      data={todo}
      editTask={editTask}
      deleteTask={deleteTask}
      changeTaskStatus={changeTaskStatus}
    />
  ))

  return (
    <Fragment>
      {!loading ? (
        <div className={styles.wrapper}>
          <p className={styles.wrapper__count}>Count: {totalTasksCount}</p>
          <form onSubmit={handleSubmit(onSubmit)} className={styles.wrapper__form}>
            <Input
              name='title'
              type='text'
              register={register}
              placeholder='Add a task'
              className={styles.wrapper__form_inp}
            />

            <Button type='submit' className={styles.wrapper__form_submit}>
              Create
            </Button>
          </form>
          <div className={styles.wrapper__list}>{renderTasks}</div>
        </div>
      ) : (
        <Loader />
      )}
    </Fragment>
  )
}

export default ToDo

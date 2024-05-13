import { type FC, useEffect, useState } from 'react'
import classNames from 'classnames'
import { useForm } from 'react-hook-form'

import { Input, Checkbox, Button } from 'components'

import type { TItemChangeSubmit, TToDoItemProps } from './types'
import styles from './ToDo.module.scss'

const ToDoItem: FC<TToDoItemProps> = ({ data, changeTaskStatus, deleteTask, editTask }) => {
  const [isEdit, setIsEdit] = useState<boolean>(false)

  const editTaskHandler = () => {
    setIsEdit(true)
  }

  const deleteHandler = (e: number) => {
    if (!isEdit) {
      deleteTask(e)
    }
  }

  const { register, handleSubmit, setValue } = useForm<any>({
    mode: 'onChange',
  })

  const isEditToggler = () => {
    setIsEdit(!isEdit)
  }

  const onSubmit = (item: TItemChangeSubmit) => {
    if (isEdit) {
      editTask(item.task, data?.id)
      isEditToggler()
    }
  }

  useEffect(() => {
    if (isEdit) {
      setValue('task', data?.title)
    }
  }, [data?.title, isEdit, setValue])

  return (
    <form onSubmit={handleSubmit(onSubmit)} className={styles.item}>
      {!isEdit && (
        <div className={styles.item__content}>
          <Checkbox onChange={value => changeTaskStatus(value, data?.id)} checked={data?.completed} />
          <p
            className={classNames(styles.item__content_text, {
              [styles.item__content_text_completed]: data?.completed,
            })}
          >
            {data?.title}
          </p>
        </div>
      )}

      {isEdit && (
        <Input
          name='task'
          type='text'
          register={register}
          className={styles.item__inp}
          containerClass={styles.item__inp_container}
        />
      )}

      <div className={styles.item__buttons}>
        <Button className={styles.item__buttons_btn} onClick={isEdit ? isEditToggler : editTaskHandler}>
          {isEdit ? 'Cancel' : 'Edit'}
        </Button>

        <Button className={styles.item__buttons_btn} type='submit' onClick={() => deleteHandler(data?.id)}>
          {isEdit ? 'Save' : 'Delete'}
        </Button>
      </div>
    </form>
  )
}

export default ToDoItem

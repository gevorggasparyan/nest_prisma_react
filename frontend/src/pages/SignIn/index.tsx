import { useEffect, type FC } from 'react'
import { isEmpty } from 'lodash'
import { useForm } from 'react-hook-form'
import { useNavigate } from 'react-router-dom'
import { yupResolver } from '@hookform/resolvers/yup'

import { loginScheme } from 'utils'
import { signIn } from 'store/auth/actions'
import { TSignInReq } from 'store/auth/types'
import { ERoutePaths } from 'libraries/router/types'
import { Button, Checkbox, Input } from 'components'
import { AuthSelectors } from 'store/auth/selectors'
import { getCookie, setCookie } from 'libraries/cookie'
import { useAppDispatch, useAppSelector } from 'libraries/redux'

import styles from './SignIn.module.scss'

const SignInConstruction: FC = () => {
  const navigate = useNavigate()

  const dispatch = useAppDispatch()
  const { data, loading } = useAppSelector(AuthSelectors.getSignIn)

  const isAuth = getCookie('token')
  const rememberMe = getCookie('rememberMe')

  const {
    register,
    handleSubmit,
    formState: { isValid, isDirty, errors },
  } = useForm<any>({
    mode: 'onChange',
    resolver: yupResolver(loginScheme),
  })

  const handleRememberMe = () => {
    rememberMe === '1' ? setCookie('rememberMe', '0') : setCookie('rememberMe', '1')
  }

  const routeTuSIgnUpHandler = () => {
    navigate(ERoutePaths.SignUp)
  }

  const onSubmit = (data: TSignInReq) => {
    dispatch(signIn(data))
  }

  useEffect(() => {
    if (!loading && !isEmpty(data?.accessToken)) {
      return navigate(ERoutePaths.Home)
    }

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, loading])

  useEffect(() => {
    if (isAuth) {
      navigate(ERoutePaths.Home)
    }
  }, [isAuth, navigate])

  return (
    <section className={styles.wrapper}>
      <h1 className={styles.wrapper_title}>Log into account</h1>

      <form onSubmit={handleSubmit(onSubmit)} className={styles.wrapper__form}>
        <Input
          type='text'
          name='username'
          label='User Name'
          register={register}
          placeholder='User name'
          error={errors?.name?.message}
        />

        <Input
          name='password'
          label='Password'
          type='password'
          register={register}
          placeholder='EnterPassword'
          error={errors?.password?.message}
        />

        <Checkbox name='remember' label={<p>remember Me</p>} onChange={handleRememberMe} />

        <Button type='submit' disabled={!isValid && isDirty} isLoading={false}>
          SignIn
        </Button>

        <Button onClick={routeTuSIgnUpHandler} className={styles.wrapper__form_create}>
          Create an account
        </Button>
      </form>
    </section>
  )
}

export default SignInConstruction

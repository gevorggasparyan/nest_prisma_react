import { useEffect, type FC } from 'react'
import { useForm } from 'react-hook-form'
import { useNavigate } from 'react-router-dom'
import { yupResolver } from '@hookform/resolvers/yup'

import { registrationScheme } from 'utils'
import { Button, Input } from 'components'
import { signUp } from 'store/auth/actions'
import { getCookie } from 'libraries/cookie'
import type { TSignUpReq } from 'store/auth/types'
import { AuthSelectors } from 'store/auth/selectors'
import { ERoutePaths } from 'libraries/router/types'
import { useAppDispatch, useAppSelector } from 'libraries/redux'

import styles from './SignUp.module.scss'

const SignUpConstruction: FC = () => {
  const navigate = useNavigate()
  const isAuth = getCookie('token')
  const dispatch = useAppDispatch()
  const { loading } = useAppSelector(AuthSelectors.getSignUp)

  const {
    register,
    handleSubmit,
    formState: { isValid, isDirty, errors },
  } = useForm<any>({
    mode: 'onChange',
    resolver: yupResolver(registrationScheme),
  })

  const routeTuSignIpHandler = () => {
    navigate(ERoutePaths.SignIn)
  }

  const onSubmit = (data: TSignUpReq) => {
    const formatSendData = {
      email: data?.email,
      password: data?.password,
      username: data?.username,
    }
    dispatch(signUp(formatSendData))
  }

  useEffect(() => {
    if (isAuth) {
      navigate(ERoutePaths.Home)
    }
  }, [isAuth, navigate])

  return (
    <section className={styles.wrapper}>
      <h1 className={styles.wrapper_title}>Sign up account</h1>

      <form onSubmit={handleSubmit(onSubmit)} className={styles.wrapper__form}>
        <Input
          type='text'
          name='username'
          label='User name'
          register={register}
          placeholder='Create your user name'
          error={errors?.userName?.message}
        />

        <Input
          name='email'
          type='email'
          label='Email'
          register={register}
          placeholder='Create your email'
          error={errors?.email?.message}
        />

        <Input
          name='password'
          type='password'
          label='Password'
          register={register}
          error={errors?.password?.message}
          placeholder='Create your password'
        />
        <Input
          type='password'
          register={register}
          label='Repeat password'
          name='passwordConfirm'
          placeholder='Repeat your password'
          error={errors?.passwordConfirm?.message}
        />

        <Button type='submit' disabled={!isValid && isDirty} isLoading={loading || undefined}>
          Sign up
        </Button>

        <Button onClick={routeTuSignIpHandler} className={styles.wrapper__form_create}>
          Sign in
        </Button>
      </form>
    </section>
  )
}

export default SignUpConstruction

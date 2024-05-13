import { object, string, ref } from 'yup'

const registrationScheme = object().shape({
  username: string()
    .required('This field is required')
    .matches(/^[^\s]+$/, 'Username without whitespace')
    .min(2, 'User name min Length 2')
    .max(30, 'Max length 30'),

  email: string()
    .required('This field is required')
    .email("Email validate don't confirmed")
    .matches(/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/, 'Email  without whitespace'),
  password: string()
    .required('This field is required')
    .min(8, 'Password min Length')
    .max(20, 'Password max Length')
    .matches(
      /^(?=(?:.*[A-Z]){1,})(?=(?:.*[a-z]){1,})(?=(?:.*\d){1,})(?=(?:.*[!@#$%^&*().\-_=+{};:,<.>]){1,})([A-Za-z0-9!@#$%^&*()\-_=+{};:,<.>]{6,20})/,
      "Password validate don't confirmed"
    )
    .test('passwords-match', 'Password must match', function (value) {
      if (this.parent.passwordConfirm) {
        return this.parent.passwordConfirm === value
      }

      return true
    }),
  passwordConfirm: string()
    .required('This field is required')
    .oneOf([ref('password')], 'Password must match'),
})

export default registrationScheme

import { object, string } from 'yup'

const loginScheme = object().shape({
  username: string()
    .required('Username required')
    .min(3, 'Minimum text length is 3 characters')
    .max(18, 'Maximum text length is 18 characters')
    .matches(/[a-zA-Z0-9]/, 'Text must contain at least one character'),
  password: string()
    .required('passwordRequired')
    .min(8, 'Password min Length 8')
    .max(20, 'Password max Length 20')
    .matches(
      /^(?=(?:.*[A-Z]){1,})(?=(?:.*[a-z]){1,})(?=(?:.*\d){1,})(?=(?:.*[!@#$%^&*().\-_=+{};:,<.>]){1,})([A-Za-z0-9!@#$%^&*()\-_=+{};:,<.>]{6,20})/,
      "Password don't validate"
    ),
})

export default loginScheme

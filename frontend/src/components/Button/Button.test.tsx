import { render, fireEvent } from '@testing-library/react'
import Button from './index'

describe('Button component', () => {
  test('renders button with correct text', () => {
    const buttonText = 'Click me'
    const { getByText } = render(<Button>{buttonText}</Button>)
    const buttonElement = getByText(buttonText)
    expect(buttonElement).toBeInTheDocument()
  })

  test('calls onClick handler when clicked', () => {
    const onClickMock = jest.fn()
    const { getByTestId } = render(<Button onClick={onClickMock}>Click me</Button>)
    const buttonElement = getByTestId('button')
    fireEvent.click(buttonElement)
    expect(onClickMock).toHaveBeenCalled()
  })

  test('disables button when isLoading is true', () => {
    const { getByTestId } = render(<Button isLoading={true}>Click me</Button>)
    const buttonElement = getByTestId('button')
    expect(buttonElement).toBeDisabled()
  })

  test('disables button when disabled prop is true', () => {
    const { getByTestId } = render(<Button disabled={true}>Click me</Button>)
    const buttonElement = getByTestId('button')
    expect(buttonElement).toBeDisabled()
  })

  test('renders Loader when isLoading is true', () => {
    const { getByTestId } = render(<Button isLoading={true}>Click me</Button>)
    const loaderElement = getByTestId('loader')
    expect(loaderElement).toBeInTheDocument()
  })
})

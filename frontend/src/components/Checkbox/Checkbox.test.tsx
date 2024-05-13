import { render, fireEvent } from '@testing-library/react'

import Checkbox from './index'

describe('Checkbox component', () => {
  it('renders without errors', () => {
    const { getByTestId } = render(<Checkbox name='test-checkbox' label='Test Checkbox' />)
    expect(getByTestId('checkbox-wrapper')).toBeInTheDocument()
  })

  it('handles onChange event properly', () => {
    const onChangeMock = jest.fn()
    const { getByTestId } = render(
      <Checkbox name='test-checkbox' label='Test Checkbox' checked={false} onChange={onChangeMock} />
    )
    const checkbox = getByTestId('checkbox-input')
    fireEvent.click(checkbox)
    expect(onChangeMock).toHaveBeenCalledWith(true, expect.any(Object))
  })
})

import { fireEvent } from '@testing-library/react'
import { BrowserRouter as Router } from 'react-router-dom'
import { render as renderWithProviders } from 'utils/test-utils'
import Header from './index'

describe('Header component', () => {
  it('renders without errors', () => {
    const { getByText } = renderWithProviders(<Header />)
    expect(getByText('Log out')).toBeInTheDocument()
  })

  it('logs out when button is clicked', () => {
    const { getByText } = renderWithProviders(<Header />)
    const logOutButton = getByText('Log out')
    fireEvent.click(logOutButton)
  })
})

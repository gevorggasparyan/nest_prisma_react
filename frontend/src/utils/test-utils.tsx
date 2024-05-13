import React, { FC, ReactElement } from 'react'
import { render, RenderOptions } from '@testing-library/react'
import { configure } from '@testing-library/dom'
import { Provider } from 'react-redux'
import { BrowserRouter } from 'react-router-dom'

import { store } from 'libraries/redux'
import ToastServices from 'libraries/toastify/toastServices'

const WithProviders: FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <BrowserRouter>
      <Provider store={store}>
        {children}

        <ToastServices />
      </Provider>
    </BrowserRouter>
  )
}

configure({ testIdAttribute: 'data-testid' })

const renderWithProviders = (ui: ReactElement, options?: Omit<RenderOptions, 'wrapper'>) =>
  render(ui, { wrapper: WithProviders, ...options })

export { default as userEvent } from '@testing-library/user-event'

export * from '@testing-library/react'
export { renderWithProviders as render }

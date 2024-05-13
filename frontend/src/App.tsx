import { Provider } from 'react-redux'
import { BrowserRouter } from 'react-router-dom'

import { store } from 'libraries/redux'
import { PageLayout } from 'components'
import ToastServices from 'libraries/toastify/toastServices'

import './styles/local.scss'

const App = () => (
  <BrowserRouter>
    <Provider store={store}>
      <PageLayout />

      <ToastServices />
    </Provider>
  </BrowserRouter>
)

export default App

declare module '*.scss' {
  const content: Record<string, string>
  export default content
}

declare module '*.png' {
  const value: any
  export default value
}

declare module '*.svg' {
  import React = require('react')

  export const ReactComponent: React.FC<React.SVGProps<SVGSVGElement>>
  const src: string
  export default src
}

declare module '*.mp4' {
  const src: string
  export default src
}

declare module '*.pdf' {
  const value: any
  export default value
}

interface Window {
  ethereum: any
}

type Address = `0x${string}`

import Dotenv from 'dotenv-webpack'

import TerserPlugin from 'terser-webpack-plugin'

module.exports = {
  module: {
    rules: [
      {
        test: /\.(scss|sass)$/,
        use: [
          'style-loader',
          'css-loader',
          'sass-loader',
          {
            loader: 'sass-resources-loader',
            options: {
              resources: ['./src/styles/vars.scss'],
            },
          },
        ],
      },
    ],
  },

  plugins: [
    new Dotenv({
      path: '.env',
      safe: '.env.example',
    }),
  ],

  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        minify: TerserPlugin.esbuildMinify,
        terserOptions: {
          compress: true,
        },
      }),
    ],
  },
}

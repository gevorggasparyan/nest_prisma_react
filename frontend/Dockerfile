FROM node:20.12.2-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN yarn install

COPY . .
RUN yarn global add serve
RUN yarn build

EXPOSE 3000

CMD [ "yarn", "start" ]

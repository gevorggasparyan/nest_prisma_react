
# To Do List Backend (NestJS/MySQL)


## Installation

```bash
$ npm install
```


## Running the app

- Create a `.env` file with these properties: 
```dotenv
DATABASE_URL="url-to-your-database"
JWT_SECRET="jwt-secret"
SALT=<number-value>
```
- Apply database schema: 
```bash
npx prisma db push
```
- Commands to run the project
```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Test

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## [Swagger URL](http://localhost:3002/api/#/)
```
http://localhost:3002/api/
```

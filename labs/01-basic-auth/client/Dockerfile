FROM node:20-alpine

WORKDIR /app

COPY package.json yarn.lock tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY labs/01-basic-auth/server ./labs/01-basic-auth/server

RUN yarn install --frozen-lockfile
RUN yarn workspace @auth-labs/shared build

WORKDIR /app/labs/01-basic-auth/server
CMD ["yarn", "start"]
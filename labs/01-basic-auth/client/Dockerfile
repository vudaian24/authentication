FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json yarn.lock tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY labs/01-basic-auth/client ./labs/01-basic-auth/client

RUN yarn install --frozen-lockfile
RUN yarn workspace @auth-labs/shared build
RUN yarn workspace @auth-labs/01-client build

FROM nginx:alpine
COPY --from=builder /app/labs/01-basic-auth/client/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
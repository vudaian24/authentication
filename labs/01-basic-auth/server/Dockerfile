FROM node:20-alpine

WORKDIR /app

# Copy packages/shared
COPY packages/shared ./packages/shared

# Copy server
COPY labs/01-basic-auth/server ./labs/01-basic-auth/server

# Copy root package.json và yarn.lock
COPY package.json yarn.lock ./

# Cài dependencies
RUN yarn install --frozen-lockfile

# Build shared
RUN yarn workspace @auth-labs/shared build

# Start server
WORKDIR /app/labs/01-basic-auth/server
CMD ["yarn", "start"]
# Authentication Labs

Hands-on labs exploring different authentication patterns (session-based, JWT, OAuth,
etc.), each as an isolated client/server pair inside a Yarn-workspaces monorepo.

## Structure

```
packages/shared/        shared TypeScript utilities used across labs
labs/01-basic-auth/      lab 1 — basic session-based auth (server + client)
labs/02..07/             planned labs (see package.json scripts)
Jenkinsfile              CI: install → build → type-check → Docker build/push
```

## Running a lab

```bash
yarn install
yarn 01   # runs labs/01-basic-auth server + client concurrently
```

## CI/CD

The `Jenkinsfile` builds the shared package, type-checks and builds lab 01's
client/server, then builds and pushes Docker images for both to Docker Hub on
`main`.

## Stack

TypeScript · Yarn workspaces · Docker · Jenkins

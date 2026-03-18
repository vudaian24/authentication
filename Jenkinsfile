pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'anvd2401/authentication'
        DOCKER_TAG = "${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'yarn install --frozen-lockfile'
            }
        }

        stage('Build Shared Package') {
            steps {
                sh 'yarn workspace @auth-labs/shared build'
            }
        }

        stage('Type Check') {
            steps {
                sh 'yarn workspace @auth-labs/01-server tsc --noEmit'
            }
        }

        stage('Build Client') {
            steps {
                sh 'yarn workspace @auth-labs/01-client build'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -f labs/01-basic-auth/server/Dockerfile -t ${DOCKER_IMAGE}-server:${DOCKER_TAG} ."
                sh "docker build -f labs/01-basic-auth/client/Dockerfile -t ${DOCKER_IMAGE}-client:${DOCKER_TAG} ."
                sh "docker tag ${DOCKER_IMAGE}-server:${DOCKER_TAG} ${DOCKER_IMAGE}-server:latest"
                sh "docker tag ${DOCKER_IMAGE}-client:${DOCKER_TAG} ${DOCKER_IMAGE}-client:latest"
            }
        }

        stage('Push Docker Hub') {
            when {
                branch 'main'
            }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-credentials',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh "echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin"
                    sh "docker push ${DOCKER_IMAGE}-server:${DOCKER_TAG}"
                    sh "docker push ${DOCKER_IMAGE}-server:latest"
                    sh "docker push ${DOCKER_IMAGE}-client:${DOCKER_TAG}"
                    sh "docker push ${DOCKER_IMAGE}-client:latest"
                }
            }
        }
    }
}

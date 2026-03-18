pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'anvd2401/auth-labs'
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

        stage('Lint') {
            steps {
                sh 'yarn lint'
            }
        }

        stage('Build Client') {
            steps {
                sh 'yarn workspace @auth-labs/01-client build'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."
                sh "docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest"
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
                    sh "docker push ${DOCKER_IMAGE}:${DOCKER_TAG}"
                    sh "docker push ${DOCKER_IMAGE}:latest"
                }
            }
        }
    }

    post {
        success {
            script {
                def message = env.BRANCH_NAME == 'main'
                    ? "✅ *Pipeline Passed*"
                    : "✅ *CI Passed* (CD skipped - PR only)"
                sendTelegram(message)
            }
        }
        failure {
            script {
                sendTelegram("❌ *Pipeline Failed*")
            }
        }
        always {
            sh 'docker logout || true'
        }
    }
}

def sendTelegram(String message) {
    withCredentials([
        string(credentialsId: 'telegram-bot-token', variable: 'BOT_TOKEN'),
        string(credentialsId: 'telegram-chat-id', variable: 'CHAT_ID')
    ]) {
        def repoName = env.GIT_URL?.tokenize('/')?.last()?.replace('.git', '') ?: 'unknown'
        def shortCommit = env.GIT_COMMIT?.take(7) ?: 'unknown'
        def fullMessage = """${message}
📦 *Repo:* `${repoName}`
🌿 *Branch:* `${env.BRANCH_NAME}`
👤 *Author:* `${env.GIT_AUTHOR_NAME}`
💬 *Commit:* `${shortCommit}`
🔗 [View Run](${env.BUILD_URL})"""

        sh """
            curl -s -X POST https://api.telegram.org/bot\${BOT_TOKEN}/sendMessage \
                -d chat_id=\${CHAT_ID} \
                -d parse_mode=Markdown \
                -d text="${fullMessage.replace('"', '\\"')}"
        """
    }
}

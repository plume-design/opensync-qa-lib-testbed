pipeline {
  agent {
    node {
      label 'pl-pxe-jenkins-1.pl.plumewifi.com||pl-pxe-jenkins-2.pl.plumewifi.com'
    }
  }
  options { timestamps () }
  environment {
    PR_CHECK = 'true'
  }
  stages {
    stage('setup') {
      steps {
        checkout([
          $class: 'GitSCM',
          branches: [[name: '*/master']],
          doGenerateSubmoduleConfigurations: false,
          extensions: [
            [
              $class: 'SubmoduleOption',
              disableSubmodules: false,
              parentCredentials: true,
              recursiveSubmodules: true,
              reference: '',
              trackingSubmodules: true
            ]
          ],
          submoduleCfg: [],
          userRemoteConfigs: [
            [
              credentialsId: 'jenkins-pytest',
              url: 'git@github.com:plume-design/autotest-testrunner.git'
            ]
          ]
        ])
        script {
          sshagent (credentials: ['jenkins-pytest']) {
            sh 'python3 lib/util/jenkins_setup.py --GIT_URL=${GIT_URL} --BRANCH_NAME=${BRANCH_NAME} --GIT_COMMIT=${GIT_COMMIT} --CHANGE_ID=${CHANGE_ID}'
          }
        }
      }
    }
    stage('run unit_test') {
      steps {
        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE'){
          sh './docker/dock-run pytest -n 3 --junitxml=./unit_test_report.xml -m tag_qa_lib_testbed ./tests/unit_tests'
        }
      }
    }
    stage('create customer env osrt') {
      steps {
        sh './docker/dock-run python ./lib/util/customer_env/customer.py osrt'
      }
    }
  }
  post {
    always {
      allure([[path: 'allure-results']])
    }
  }
}

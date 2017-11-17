node('docker') {
     stage('checkout') {
        checkout scm
     }
     stage('use-fbelzunc-docker-fixtures') {
             sh '''
             git clone https://github.com/jenkinsci/docker-fixtures.git
             cd docker-fixtures
             git fetch origin pull/4/head:JENKINS-46673
             git checkout JENKINS-46673
             mvn clean install
             '''
    }
     stage('docker-pull') {
        sh 'docker pull fbelzunc/ad-build-container'
     }
     stage('maven') {
        sh 'docker run --add-host=samdom.example.com:127.0.0.1 -v /var/lib/docker --privileged --dns=127.0.0.1 --dns=8.8.8.8 -v $WORKSPACE:/project  fbelzunc/ad-build-container'
     }
     stage('surefire-report') {
        junit 'target/surefire-reports/*.xml'
     }
}
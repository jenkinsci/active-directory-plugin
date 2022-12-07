buildPlugin(configurations: [
    [platform: 'linux', jdk: '11'],
    [platform: 'windows', jdk: '11'],
], useContainerAgent: false)

node('docker') {
     stage('checkout') {
        checkout scm
     }

     stage('maven') {
        sh 'docker build -t fixture src/test/resources/fixture && docker run --add-host=samdom.example.com:127.0.0.1 -v /var/lib/docker --privileged --dns=127.0.0.1 --dns=8.8.8.8 -v $WORKSPACE:/project fixture clean install -P onlyITs'
     }

     stage('surefire-report') {
        junit 'target/surefire-reports/*.xml'
     }
}

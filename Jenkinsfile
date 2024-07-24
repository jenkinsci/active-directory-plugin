buildPlugin(useContainerAgent: false, configurations: [
  [platform: 'linux', jdk: 21],
  [platform: 'linux', jdk: 11],
  [platform: 'windows', jdk: 17],
])

node('docker') {
     stage('checkout') {
        checkout scm
     }

     stage('maven') {
        // Maven tests will start a dummy AD service at samdom.example.com
        sh '''
        docker run --rm -v /etc:/host-etc:rw --user=root --entrypoint=sh alpine -c "echo '127.0.0.1 samdom.example.com' >> /host-etc/hosts"
        '''
        sh 'mvn -B -Djenkins.test.timeout=1200 fixture clean install -P onlyITs'
     }

     stage('surefire-report') {
        junit 'target/surefire-reports/*.xml'
     }
}

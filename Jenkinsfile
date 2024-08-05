/*buildPlugin(useContainerAgent: false, configurations: [
  [platform: 'linux', jdk: 21],
  [platform: 'linux', jdk: 11],
  [platform: 'windows', jdk: 17],
])
*/

node('docker') {
     stage('checkout') {
        checkout scm
     }

     stage('maven') {
        sh 'sudo ./hack_systemd_resolve.sh'
        sh 'mvn clean install -P onlyITs'
     }

     stage('surefire-report') {
        junit 'target/surefire-reports/*.xml'
     }
}

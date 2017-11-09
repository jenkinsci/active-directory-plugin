node('docker') {
     checkout scm
     sh 'ps'
     sh 'pwd'
     sh 'ls -la'
     sh 'docker pull fbelzunc/ad-build-container'
     //-v /var/lib/docker:/var/lib/docker
     sh 'docker run --add-host=samdom.example.com:127.0.0.1 -v /var/lib/docker --privileged --dns=127.0.0.1 --dns=8.8.8.8 -v $WORKSPACE:/project  fbelzunc/ad-build-container'
     junit 'target/surefire-reports/*.xml'
}

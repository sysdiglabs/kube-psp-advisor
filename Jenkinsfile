pipeline {
  agent {
    label 'builder-backend-j8'
  }

  stages {
    stage("Build") {
      steps {
        dir(".") {
    	    script {
            sh "ls && pwd && echo $PWD && docker run --rm -v \$(pwd):/usr/src/myapp -w /usr/src/myapp golang:1.13 make build"
          } 
        }
      }
    }
    stage("Tests") {
      steps {
        dir(".") {
	        script {
            sh "docker run --rm -v \$(pwd):/usr/src/myapp -w /usr/src/myapp golang:1.13 go test ./..."
          } 
        }
      }
    }
  }
}

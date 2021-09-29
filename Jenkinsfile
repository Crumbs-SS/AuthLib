pipeline{

    agent any

      tools {
            maven 'maven'
            jdk 'java'
      }

  stages{


      stage("package"){
            steps{
                sh 'mvn clean install'
            }
      }

  }
  post {
          always {
              sh 'mvn clean'
          }
      }

}

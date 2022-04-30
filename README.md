# Spring Boot + JWT Token

## Implementation of authentication and authorization with JWT token

Its a sample application for implementing JWT token validation.
In any project you can copy security folder and can easily attain token implementation through small changes.

### Guidelines
You have to follow below points for attaining the features based on your project.
* Implement database connectivity details in application.property file and add needed dependencies in pom file.
* Add your own business logic in AppUserDetails class after reading inline comments.
* Use AppAuthorizeRequestMatchers class for adding url permission and roles.
* Point out exact login and refresh page url path in filter and AppSecurityConfig, in this application used login and refresh page url are "/session/login" and "/session/refresh"


### Platform 
* Java 11
* Spring Boot 2.6.6
* JWT Auto0 3.18.1

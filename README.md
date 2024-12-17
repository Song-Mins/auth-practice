## 📚 Spring Security, JWT, OAuth2 를 활용한 여러가지 인증, 인가 구현
이 프로젝트에서는 **Spring Security** 를 기반으로 **JWT**, **OAuth2** 를 활용하여 다양한 인증 및 인가 방법을 학습하고 구현한다.   
</br>

  
## ✏️ 브랜치 종류
### security-session 
- Spring Security 의 세션 기반 인증 및 인가 구현   

### security-jwt 
- Spring Security 와 JWT 를 활용한 인증 및 인가 구현   

### security-session-oauth2 
- Spring Security 의 세션과 OAuth2 를 활용한 인증 및 인가 구현   

### security-jwt-oauth2 
- Spring Security 와 JWT, 그리고 OAuth2 를 활용한 인증 및 인가 구현   
</br>

## ✏️ 브랜치 설명
각 브랜치별 인증/인가 방벙의 특징에 대한 간단한 설명이다.  
실제 구현 방법에 대한 내용은 각 브랜치의 리드미 파일에 작성되어 있다.
### security-session
  - Spring Security 의 세션 기반 인증 및 인가를 구현
    
- 특징
  - 사용자가 로그인하면 서버에서 세션을 생성하고 이를 관리
  - 쿠키에 세션 ID를 저장하며, 서버는 이를 통해 사용자를 식별
  - 상태 기반 인증 방식으로 서버가 상태를 유지
  - 서버 부하가 커질 수 있으며, 분산 서버 환경에서는 세션의 정합성 문제를 해결하기 위해 추가적인 작업이 필요
  - 일반적으로 내부 애플리케이션에서 사용됩니다.

- 적합한 상황:
  - 서버와 클라이언트가 신뢰할 수 있는 환경 (예: 사내 시스템)
  - 인증 정보가 외부에 노출되지 않아야 하는 경우
  - 세션 공유 및 유지 비용이 허용되는 소규모 또는 중간 규모 애플리케이션

### security-jwt
- Spring Security 와 JWT 를 활용한 인증 및 인가 구현

- 특징
  - 사용자가 로그인하면 서버는 JWT 를 생성하여 클라이언트에게 전달
  - 클라이언트는 요청 시 이 토큰을 헤더에 포함하며, 서버는 토큰을 검증하여 인증을 처리
  - 상태 비저장 인증 방식으로, 서버는 인증 정보를 유지하지 않음
  - 확장성이 뛰어나며, 분산 서버 환경에서 별도의 세션 공유가 필요 없음
  - 토큰이 클라이언트에 저장되므로, 보안에 주의 해야됨

- 적합한 상황
  - 분산 시스템 또는 마이크로서비스 아키텍처
  - RESTful API 에서 상태를 유지하지 않고 인증을 처리해야 하는 경우
  - 확장성과 높은 응답 속도가 필요한 대규모 애플리케이션

3. security-session-oauth2
- Spring Security 세션과 OAuth2 를 활용한 인증 및 인가 구현 

- 특징
  - OAuth2를 통해 Google, Facebook, GitHub 등의 외부 인증 제공자를 활용하여 사용자 인증을 처리합니다.
  - 인증 후 세션을 생성하여 서버에서 상태를 관리합니다.
  - 외부 인증 제공자와의 통합이 가능하므로, 사용자가 별도의 계정을 생성하지 않아도 됩니다.
  - OAuth2 제공자가 인증 과정을 처리하므로, 인증의 책임이 서버에서 클라이언트로 일부 이전됩니다.
  - 세션을 활용하므로, 서버에서 상태를 유지해야 합니다.

- 적합한 상황:
  - 소셜 로그인 기능이 필요한 애플리케이션.
  - 사용자 경험을 향상시키기 위해 별도의 회원가입 절차를 줄이고 싶은 경우.
  - 세션 관리가 가능한 내부 또는 소규모 애플리케이션.

### security-jwt-oauth2
- Spring Security 와 JWT, 그리고 OAuth2 를 활용한 인증 및 인가 구현

- 특징
  - OAuth2 를 통해 인증을 수행하고, 인증 결과를 JWT로 발급받아 상태 비저장 방식으로 유지합니다. 
  - OAuth2 인증의 장점과 JWT의 상태 비저장 특성을 결합하여 구현
  - 세션 없이도 OAuth2 인증 정보를 유지 가능
  - 분산 환경에서 특히 유용하며, 토큰 기반 인증의 단점(예: 토큰 탈취)에 대한 추가 보안 조치가 필요
    
- 적합한 상황:
  - 분산 시스템, 마이크로서비스 환경
  - 클라이언트/서버 간의 인증 정보를 안전하게 전달해야 하는 대규모 애플리케이션
  - 소셜 로그인과 상태 비저장 인증이 동시에 필요한 경우



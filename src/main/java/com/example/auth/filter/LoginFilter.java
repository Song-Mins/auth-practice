package com.example.auth.filter;

import com.example.auth.dto.CustomUserDetails;
import com.example.auth.jwt.RefreshToken;
import com.example.auth.jwt.RefreshTokenService;
import com.example.auth.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;

        // 필터가 처리하는 경로 지정
        setFilterProcessesUrl("/api/user/login");
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // username, password 가져오기
        String email = request.getParameter("username");
        String password = request.getParameter("password");

        // 로그인 정보담은 인증 객체를 매니저로 전달
        // 매니저에서 로그인 처리
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, password, null);
        return authenticationManager.authenticate(authToken);
    }

    // 로그인에 성공하면
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // 인증 객체로 부터 id, role 가져옴
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        Long id = customUserDetails.getId();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // Access Token, Refresh Token 생성
        String accessToken = jwtUtil.createAccessToken(id, role, 60*1000*60); // 60분
        String refreshToken = jwtUtil.createRefreshToken(60*60*1000*24); // 24시간

        // Refresh Token 레디스에 저장
        RefreshToken refreshTokenEntity = new RefreshToken(id, role, accessToken, refreshToken);
        refreshTokenService.saveTokenInfo(refreshTokenEntity);

        // 응답 헤더에 Access Token 추가
        response.addHeader("Authorization", "Bearer " + accessToken);
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        // 다시 로그인해라고 알림
        response.setStatus(401);
    }
}

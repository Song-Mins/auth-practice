package com.example.auth.filter;

import com.example.auth.dto.CustomUserDetails;
import com.example.auth.entity.User;
import com.example.auth.jwt.RefreshToken;
import com.example.auth.jwt.RefreshTokenService;
import com.example.auth.service.UserService;
import com.example.auth.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Access Token 추출하기
        String accessToken = resolveToken(request);

        // null 이면 다음 필터로 이동
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        //  Access Token 유효한지 검증
        if (!jwtUtil.validateAccessToken(accessToken)) {

            // Access Token 유효하지 않으면
            // redis 로부터 해당 Refresh Token 가져옴
            RefreshToken refreshTokenEntity = refreshTokenService.findTokenInfo(accessToken);
            String refreshToken = refreshTokenEntity.getRefreshToken();

            // Refresh Token 유효한지 검증
            if (!jwtUtil.validateRefreshToken(refreshToken)) {

                // Refresh Token 유효하지 않으면
                // 다시 로그인해라고 알림
                response.setStatus(401);
                return;
            }

            // Refresh Token 유효하면
            // 새로운 Access Token 생성하고 응답헤더에 추가
            accessToken = jwtUtil.createAccessToken(refreshTokenEntity.getId(), refreshTokenEntity.getRole(),
                60 * 1000 * 60); // 60분
            response.addHeader("Authorization", "Bearer " + accessToken);

            // Refresh Token 도 다시 생성해서 레디스에 저장
            refreshToken = jwtUtil.createRefreshToken(60*60*1000*24); // 24시간
            refreshTokenEntity = new RefreshToken(refreshTokenEntity.getId(), refreshTokenEntity.getRole(), accessToken, refreshToken);
            refreshTokenService.saveTokenInfo(refreshTokenEntity);

        }

        // Access Token 유효 하거나 새로운 Access Token 생성되면
        // Access Token 으로 부터 User 생성
        Long id = jwtUtil.getId(accessToken);
        String role = jwtUtil.getRole(accessToken);
        User user = User.of(id, role);

        // CustomUserDetails 생성
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // SecurityContextHolder 저장하고 다음 필터로~
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null,
            customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {

        // 요청 헤더로부터 Authorization 값 가져옴
        String authorization = request.getHeader("Authorization");

        // Authorization 값이 유효하지 않으면 null 리턴
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }

        // Authorization 값으로 부터 AccessToken 추룰 - "Bearer " 부분 제거
        return authorization.substring(7);
    }
}

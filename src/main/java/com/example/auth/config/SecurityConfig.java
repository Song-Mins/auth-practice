package com.example.auth.config;

import com.example.auth.filter.JWTFilter;
import com.example.auth.filter.LoginFilter;
import com.example.auth.jwt.RefreshTokenService;
import com.example.auth.service.UserService;
import com.example.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final UserService userService;
	private final RefreshTokenService refreshTokenService;
	private final AuthenticationConfiguration authenticationConfiguration;
	private final JWTUtil jwtUtil;

	@Bean
	public AuthenticationManager authenticationManager() throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public RoleHierarchy roleHierarchy() {
		return RoleHierarchyImpl.withDefaultRolePrefix()
			.role("ADMIN").implies("MANAGER")
			.role("MANAGER").implies("USER")
			.build();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

		// JWT 이용할거임
		http
			.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable);

		// 자원에 대한 권한 설정
		http
			.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/api/register", "/api/login").permitAll()
				.anyRequest().authenticated()
			);

		// 필터 등록
		http
			.addFilterBefore(new JWTFilter(jwtUtil, refreshTokenService, userService), LoginFilter.class);
		http
			.addFilterAt(new LoginFilter(authenticationManager(), jwtUtil, refreshTokenService), UsernamePasswordAuthenticationFilter.class);

		// 세션 사용 X
		// STATELESS 지만 해당 요청이 처리되는 동안에는 세션이 생성되고 요청이 끝나면 세션 소멸
		http
			.sessionManagement((session) -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}



}

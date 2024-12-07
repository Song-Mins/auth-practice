package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

		http
			.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
				.requestMatchers("/admin").hasRole("ADMIN")
				.requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
				.anyRequest().authenticated()
			);

		http
			.formLogin((auth) -> auth.loginPage("/login")
				.loginProcessingUrl("/loginProc")
				.permitAll()
			);

		http
			.csrf((auth) -> auth.disable());

		// 동시 세션 제어
		http
			.sessionManagement((auth) -> auth
//				.invalidSessionUrl("/invalid") // 세션 유요하지 않을 때 이동할 페이지
				.maximumSessions(1)
//				.expiredUrl("/expired") // 세션이 만료된 경우 이동할 페이지
				.maxSessionsPreventsLogin(true)); // false : 이전 사용자 세션 만료 / true : 현재 사용자 인증 실패
		// invalidSessionUrl 과 expiredUrl 둘 다 설정된 경우 invalidSessionUrl 이 우선순위


		return http.build();
	}



}

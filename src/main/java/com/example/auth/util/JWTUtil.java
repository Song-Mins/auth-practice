package com.example.auth.util;

import io.jsonwebtoken.Jwts;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

	private final SecretKey accessSecretKey;
	private final SecretKey refreshSecretKey;

	public JWTUtil(
		@Value("${spring.jwt.access-secret}") String accessSecret,
		@Value("${spring.jwt.refresh-secret}") String refreshSecret
	) {
		this.accessSecretKey = new SecretKeySpec(accessSecret.getBytes(StandardCharsets.UTF_8),
			Jwts.SIG.HS256.key().build().getAlgorithm());
		this.refreshSecretKey = new SecretKeySpec(refreshSecret.getBytes(StandardCharsets.UTF_8),
			Jwts.SIG.HS256.key().build().getAlgorithm());
	}

	public String getEmail(String token) {
		return Jwts.parser().verifyWith(accessSecretKey).build().parseSignedClaims(token)
			.getPayload().get("email", String.class);
	}

	public String getRole(String token) {
		return Jwts.parser().verifyWith(accessSecretKey).build().parseSignedClaims(token)
			.getPayload().get("role", String.class);
	}

	public Long getId(String token) {
		return Jwts.parser().verifyWith(accessSecretKey).build().parseSignedClaims(token)
			.getPayload().get("id", Long.class);
	}

	public Boolean validateAccessToken(String token) {

		try {
			return Jwts.parser().verifyWith(accessSecretKey).build().parseSignedClaims(token)
				.getPayload().getExpiration().after(new Date());
		} catch (Exception e) {
			return false;
		}

	}

	public Boolean validateRefreshToken(String token) {

		try {
			return Jwts.parser().verifyWith(refreshSecretKey).build().parseSignedClaims(token)
				.getPayload().getExpiration().after(new Date());
		} catch (Exception e) {
			return false;
		}
	}


	public String createAccessToken(Long id, String role, long expiredMs) {
		return Jwts.builder()
			.claim("id", id)
			.claim("role", role)
			.issuedAt(new Date(System.currentTimeMillis()))
			.expiration(new Date(System.currentTimeMillis() + expiredMs))
			.signWith(accessSecretKey)
			.compact();
	}

	public String createRefreshToken(long expiredMs) {

		return Jwts.builder()
			.claim("id", UUID.randomUUID().toString())
			.issuedAt(new Date(System.currentTimeMillis()))
			.expiration(new Date(System.currentTimeMillis() + expiredMs))
			.signWith(refreshSecretKey)
			.compact();
	}


}
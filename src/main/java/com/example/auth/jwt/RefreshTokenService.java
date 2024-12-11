package com.example.auth.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	@Transactional
	public void saveTokenInfo(RefreshToken refreshToken) {
		refreshTokenRepository.save(refreshToken);
	}

	@Transactional
	public RefreshToken findTokenInfo(String accessToken) {

		return refreshTokenRepository.findByAccessToken(accessToken)
			.orElseThrow(
				() -> new RuntimeException("해당 액세스 토큰의 리프레시 토큰 없음")
			);
	}

	@Transactional
	public void removeRefreshToken(String accessToken) {
		refreshTokenRepository.findByAccessToken(accessToken)
			.ifPresent(refreshTokenRepository::delete);
	}

}

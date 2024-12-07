package com.example.auth.service;

import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RegisterService {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;


	public void create(RegisterRequest registerRequest) {
		User user = User.of(registerRequest.getUsername(),
			bCryptPasswordEncoder.encode(registerRequest.getPassword()),
			"ROLE_USER");

		userRepository.save(user);
	}
}

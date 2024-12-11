package com.example.auth.controller;

import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/register")
@RequiredArgsConstructor
public class RegisterController {

	private final UserService userService;

	@PostMapping
	public String register(RegisterRequest registerRequest) {
		userService.create(registerRequest);
		return "success";
	}
}

package com.example.auth.controller;

import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.RegisterService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/register")
@RequiredArgsConstructor
public class RegisterController {

	private final RegisterService registerService;

	@PostMapping
	public String register(RegisterRequest registerRequest) {
		registerService.create(registerRequest);
		return "success";
	}
}

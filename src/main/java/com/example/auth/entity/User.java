package com.example.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;

@Entity
@Getter
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;
	private String username;
	private String password;
	private String role;

	public User() {}

	private User(String username, String password, String role) {
		this.username = username;
		this.password = password;
		this.role = role;
	}

	public static User of(String username, String password, String role) {
		return new User(username, password, role);
	}
}
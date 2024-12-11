package com.example.auth.repository;

import com.example.auth.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

	default User getUserByUsername(String username) {
		return findByUsername(username).orElseThrow(
			() -> new RuntimeException("없는 사용자")
		);
	}
}

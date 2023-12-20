package com.springsecurity.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.springsecurity.security.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);
    User findByRole(Enum role);
}

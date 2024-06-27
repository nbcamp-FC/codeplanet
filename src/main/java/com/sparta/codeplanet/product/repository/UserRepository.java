package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.global.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

import org.springframework.data.repository.cdi.Eager;
import org.springframework.stereotype.Repository;


public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findUserByUsername(String username);
    Optional<User> findUserByUsernameAndStatus(String username, Status active);
    Optional<User> findByEmail(String email);
}

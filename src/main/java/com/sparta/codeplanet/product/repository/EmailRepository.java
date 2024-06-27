package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.Email;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailRepository extends JpaRepository<Email, Long> {
    Optional<Email> findByEmail(String email);
}

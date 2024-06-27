package com.sparta.codeplanet.product.repository;

import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.entity.UserRefreshToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRefreshTokenRepository extends JpaRepository<UserRefreshToken, Long> {
    Optional<UserRefreshToken> findByIdAndReissueCountLessThan(Long id, long count);

    Optional<UserRefreshToken> findByRefreshToken(String refreshToken);

}
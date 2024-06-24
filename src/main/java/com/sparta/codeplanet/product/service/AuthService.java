package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.entity.UserRefreshToken;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import io.jsonwebtoken.Claims;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TokenProvider tokenProvider;

    /**
     * 토큰 재발급 메서드
     * @param refreshToken
     * @return
     */
    @Transactional
    public void reissue(String refreshToken) {
        Claims claims = tokenProvider.getUserInfoFromToken(refreshToken);

    }
}

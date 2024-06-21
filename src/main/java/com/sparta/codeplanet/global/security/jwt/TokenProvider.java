package com.sparta.codeplanet.global.security.jwt;

import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.entity.UserRefreshToken;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class TokenProvider {

    // access 토큰 헤더
    public static final String AUTH_ACCESS_HEADER = "AccessToken";
    // refresh 토큰 헤더
    public static final String AUTH_REFRESH_HEADER = "RefreshToken";
    // 사용자 권한
    public static final String AUTHORIZATION_KEY = "auth";
    // 토큰 식별자
    public static final String BEARER_PREFIX = "Bearer ";

    private final String secretKey;
    private final long expirationHours;
    private final long refreshExpirationHours;
    private final long reissueLimit;
    private final UserRefreshTokenRepository userRefreshTokenRepository;    // 추가

    private final SignatureAlgorithm SIG = SignatureAlgorithm.HS256;

    private final Key key;


    private final ObjectMapper objectMapper = new ObjectMapper();    // JWT 역직렬화를 위한 ObjectMapper
    private final UserRepository userRepository;

    public TokenProvider(
        @Value("${JWT_KEY}") String secretKey,
        @Value("${ACCESS_EXPIRATION}") long expirationHours,
        @Value("${REFRESH_EXPIRATION}") long refreshExpirationHours,
        UserRefreshTokenRepository userRefreshTokenRepository,
        UserRepository userRepository) {
        this.secretKey = secretKey;
        this.expirationHours = expirationHours;
        this.refreshExpirationHours = refreshExpirationHours;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
        reissueLimit = refreshExpirationHours * 60 / expirationHours;    // 재발급 한도

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = hmacShaKeyFor(keyBytes);
        this.userRepository = userRepository;
    }

    public String createAccessToken(String username, UserRole role) {
        return BEARER_PREFIX + Jwts.builder()
            .signWith(key, SIG)
            .setSubject(username)
            .claim(AUTHORIZATION_KEY, role)
            .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))
            .setExpiration(Date.from(Instant.now().plus(expirationHours, ChronoUnit.HOURS)))
            .compact();
    }

    public String createRefreshToken(String username, UserRole role) {
        return BEARER_PREFIX+ Jwts.builder()
            .signWith(key, SIG)
            .setSubject(username)
            .claim(AUTHORIZATION_KEY, role)
            .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))
            .setExpiration(
                Date.from(Instant.now().plus(refreshExpirationHours, ChronoUnit.HOURS)))
            .compact();
    }

    public String validateTokenAndGetSubject(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(secretKey.getBytes())
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    /**
     * 리프레시 토큰 발행에 제한을 두었을 때, 만족하는 것을 찾지 못하면 ExpiredJwtException을 터트린다. 이것을 막기 위해서 @Transactional을
     * 통해 영속성 컨텍스트로 관리해 줍니다.
     *
     * @param oldAccessToken
     * @return
     * @throws JsonProcessingException
     */
    @Transactional
    public String recreateAccessToken(String oldAccessToken) throws JsonProcessingException {
        String subject = decodeJwtPayloadSubject(oldAccessToken);
        Long userId = Long.parseLong(decodeJwtPayloadSubject(oldAccessToken));
        Optional<User> user = userRepository.findById(userId);
        userRefreshTokenRepository.findByIdAndReissueCountLessThan(
                userId, reissueLimit)
            .ifPresentOrElse(
                UserRefreshToken::increaseReissueCount,
                () -> {
                    throw new ExpiredJwtException(null, null, "Refresh token expired.");
                }
            );
        return createAccessToken(user.get().getUsername(), user.get().getUserRole());
    }

    public boolean validateToken(String token) {
        log.info("validateToken start");
        log.info("token: {}", token);
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            // refresh token 활용해서 재발급
            log.info("Expired JWT Token", e);
            throw e;
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    /**
     * 리프레스 토큰 자체가 유효한 토큰인지를 검증합니다.
     *
     * @param refreshToken
     * @param oldAccessToken
     * @throws JsonProcessingException
     */
    @Transactional(readOnly = true)
    public void validateRefreshToken(String refreshToken, String oldAccessToken)
        throws JsonProcessingException {
        getUserInfoFromToken(refreshToken);
        Long userId = Long.parseLong(decodeJwtPayloadSubject(oldAccessToken).split(":")[0]);
        userRefreshTokenRepository.findByIdAndReissueCountLessThan(userId, reissueLimit)
            .filter(memberRefreshToken -> memberRefreshToken.validateRefreshToken(refreshToken))
            .orElseThrow(() -> new ExpiredJwtException(null, null, "Refresh token expired."));
    }

    // 사용자 엔티티에 있는 refresh 토큰 만료 여부를 확인합니다.
    public boolean existRefreshToken(String refreshToken) throws JsonProcessingException {
        Long userId = Long.parseLong(decodeJwtPayloadSubject(refreshToken));
        User user = userRepository.findById(userId).orElseThrow(
            () -> new RuntimeException("User not found"));
        return user.getRefresh();
    }


    private String decodeJwtPayloadSubject(String oldAccessToken) throws JsonProcessingException {
        return objectMapper.readValue(
            new String(Base64.getDecoder().decode(oldAccessToken.split("\\.")[1]),
                StandardCharsets.UTF_8),
            Map.class
        ).get("sub").toString();
    }

    // 헤더에서 access 토큰 가져오기
    public String getAccessTokenFromHeader(HttpServletRequest request) {
        String accessToken = request.getHeader(AUTH_ACCESS_HEADER);
        if (StringUtils.hasText(accessToken) && accessToken.startsWith(BEARER_PREFIX)) {
            return accessToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    // 헤더에서 refresh 토큰 가져오기
    public String getRefreshTokenFromHeader(HttpServletRequest request) {
        String refreshToken = request.getHeader(AUTH_REFRESH_HEADER);
        if (StringUtils.hasText(refreshToken) && refreshToken.startsWith(BEARER_PREFIX)) {
            return refreshToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    // 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    // 헤더에 access 토큰 담기
    public void setHeaderAccessToken(HttpServletResponse response, String newAccessToken) {
        response.setHeader(AUTH_ACCESS_HEADER, newAccessToken);
    }

}
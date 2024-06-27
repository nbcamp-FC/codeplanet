package com.sparta.codeplanet.global.security.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.global.security.UserDetailsServiceImpl;
import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final UserDetailsServiceImpl userDetailsService;

    public JwtAuthorizationFilter(TokenProvider tokenProvider,
            UserDetailsServiceImpl userDetailsService) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String accessToken = tokenProvider.getAccessTokenFromHeader(request);

        if (StringUtils.hasText(accessToken)) {
            if (tokenProvider.validateToken(accessToken)) {
                validToken(accessToken);
            } else {
                invalidToken(request, response);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void validToken(String token) {
        Claims info = tokenProvider.getUserInfoFromToken(token);

        try {
            setAuthentication(info.getSubject());
        } catch (Exception e) {
            log.error("username = {}, message = {}", info.getSubject(), "인증 정보를 찾을 수 없습니다.");
            throw new CustomException(ErrorType.NOT_FOUND_AUTHENTICATION_INFO);
        }
    }

    private void invalidToken(HttpServletRequest request, HttpServletResponse response)
            throws JsonProcessingException {
        String refreshToken = tokenProvider.getRefreshTokenFromHeader(request);

        if (StringUtils.hasText(refreshToken)) {
            if (tokenProvider.validateToken(refreshToken) && tokenProvider.existRefreshToken(refreshToken)) {
                Claims info = tokenProvider.getUserInfoFromToken(refreshToken);

                UserRole role = UserRole.valueOf(info.get(AuthEnum.AUTHORIZATION_KEY).toString());

                String newAccessToken = tokenProvider.createAccessToken(info.getSubject(), role);

                tokenProvider.setHeaderAccessToken(response, newAccessToken);

                try {
                    setAuthentication(info.getSubject());
                } catch (Exception e) {
                    log.error("username = {}, message = {}", info.getSubject(), "인증 정보를 찾을 수 없습니다.");
                    throw new CustomException(ErrorType.NOT_FOUND_AUTHENTICATION_INFO);
                }
            } else {
                throw new CustomException(ErrorType.INVALID_REFRESH_TOKEN);
            }
        }
    }

    // 인증 처리
    private void setAuthentication(String accountId) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(accountId);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    // 인증 객체 생성
    private Authentication createAuthentication(String accountId) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(accountId);
        log.info("username = {}", userDetails.getAuthorities());
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
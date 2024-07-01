package com.sparta.codeplanet.global.security.filter;

import static com.sparta.codeplanet.product.dto.ApiResponse.success;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.ExceptionDto;
import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.dto.ApiResponse;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthorizationFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            String accessToken = tokenProvider.getAccessTokenFromHeader(request);
            if (tokenProvider.validateToken(accessToken)) {
                User user = parseUserSpecification(accessToken);
                AbstractAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                        user, accessToken, user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                throw new ExpiredJwtException(null, null, "Access token expired");
            }
        } catch (ExpiredJwtException e) {
            reissueAccessToken(request, response, e);
            return; // Ensure the response is sent after reissuing the token
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
        filterChain.doFilter(request, response);
    }

    private User parseUserSpecification(String token) {
        String[] split = Optional.ofNullable(token)
                .filter(subject -> subject.length() >= 10)
                .map(tokenProvider::validateTokenAndGetSubject)
                .orElse("anonymous:anonymous")
                .split(":");

        return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
    }

    private void reissueAccessToken(HttpServletRequest request, HttpServletResponse response,
            Exception exception) throws IOException {
        try {
            String refreshToken = tokenProvider.getRefreshTokenFromHeader(request);
            if (refreshToken == null) {
                throw exception;
            }
            String oldAccessToken = tokenProvider.getAccessTokenFromHeader(request);
            tokenProvider.validateRefreshToken(refreshToken, oldAccessToken);

            String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
            User user = parseUserSpecification(newAccessToken);
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
                    user, newAccessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            response.setHeader(AuthEnum.ACCESS_TOKEN.getValue(), "Bearer " + newAccessToken);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.success("Access token reissued successfully")));
            response.getWriter().flush();

            log.info("Access token reissued: {}", newAccessToken);
        } catch (Exception e) {
            request.setAttribute("exception", e);
            ErrorType errorType = ErrorType.INVALID_REFRESH_TOKEN;
            response.setStatus(errorType.getHttpStatus().value());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(new ExceptionDto(errorType)));
            response.getWriter().flush();
        }
    }
}

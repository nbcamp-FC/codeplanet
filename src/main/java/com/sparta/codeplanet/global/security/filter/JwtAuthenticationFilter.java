package com.sparta.codeplanet.global.security.filter;

import static com.sparta.codeplanet.global.enums.ResponseMessage.SUCCESS_LOGIN;
import static com.sparta.codeplanet.global.enums.ResponseMessage.SUCCESS_LOGOUT;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.global.exception.ExceptionDto;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.dto.ApiResponse;
import com.sparta.codeplanet.product.dto.LoginRequestDto;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.entity.UserRefreshToken;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final UserRefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String[] AUTH_WHITELIST = {
            "/users",
            "/users/login",
            "/emails"
    };

    public JwtAuthenticationFilter(TokenProvider tokenProvider, UserRepository userRepository,
            UserRefreshTokenRepository userRefreshTokenRepository,
            AuthenticationManager authenticationManager) {
        this.tokenProvider = tokenProvider;
        this.userRepository = userRepository;
        this.refreshTokenRepository = userRefreshTokenRepository;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        if (isWhitelisted(requestURI)) {
            if ("/users/login".equals(requestURI)) {
                try {
                    attemptAuthentication(request, response);
                } catch (AuthenticationException e) {
                    unsuccessfulAuthentication(request, response, e);
                }
                return;
            } else if ("/users/logout".equals(requestURI)) {
                processLogout(request, response);
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String accessToken = resolveToken(request, AuthEnum.ACCESS_TOKEN.getValue());
            if (accessToken != null) {
                try {
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
                }
            }
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
        filterChain.doFilter(request, response);
    }

    private boolean isWhitelisted(String requestURI) {
        for (String url : AUTH_WHITELIST) {
            if (requestURI.startsWith(url)) {
                return true;
            }
        }
        return false;
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
            Exception exception) {
        try {
            String refreshToken = resolveToken(request, AuthEnum.REFRESH_TOKEN.getValue());
            if (refreshToken == null) {
                throw exception;
            }
            String oldAccessToken = resolveToken(request, AuthEnum.ACCESS_TOKEN.getValue());
            tokenProvider.validateRefreshToken(refreshToken, oldAccessToken);

            String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
            User user = parseUserSpecification(newAccessToken);
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
                    user, newAccessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            response.setHeader(AuthEnum.ACCESS_TOKEN.getValue(), "Bearer " + newAccessToken);

            // Add the message to the response
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(ApiResponse.success("Access token reissued successfully")));
            response.getWriter().flush();

            // Log the reissued token
            log.info("Access token reissued: {}", newAccessToken);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
    }

    public void attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        LoginRequestDto requestDto = objectMapper.readValue(request.getInputStream(),
                LoginRequestDto.class);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        requestDto.getUsername(),
                        requestDto.getPassword()
                )
        );

        successfulAuthentication(request, response, authentication);
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication auth)
            throws IOException, ServletException {
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
        com.sparta.codeplanet.product.entity.User user = userDetails.getUser();

        if (Status.DEACTIVATE.equals(user.getStatus())) {
            throw new CustomException(ErrorType.DEACTIVATE_USER);
        }

        String username = userDetails.getUsername();
        UserRole role = user.getUserRole();

        String accessToken = tokenProvider.createAccessToken(username, role);
        String refreshToken = tokenProvider.createRefreshToken(username, role);

        // Logging token creation
        log.info("AccessToken created: {}", accessToken);
        log.info("RefreshToken created: {}", refreshToken);

        user.setRefresh(false);
        userRepository.save(user);

        UserRefreshToken userRefreshToken = refreshTokenRepository.findByUser(user);
        if (userRefreshToken != null) {
            userRefreshToken.updateRefreshToken(refreshToken);
            userRefreshToken.invalidate(false);
        } else {
            refreshTokenRepository.save(new UserRefreshToken(user, refreshToken));
        }

        response.addHeader(AuthEnum.ACCESS_TOKEN.getValue(), accessToken);
        response.addHeader(AuthEnum.REFRESH_TOKEN.getValue(), refreshToken);


        // Construct JSON response
        String jsonResponse = String.format("{\"accessToken\": \"%s\", \"refreshToken\": \"%s\", \"message\": \"%s\"}",
                accessToken, refreshToken, SUCCESS_LOGIN.getMessage());

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        ErrorType errorType = ErrorType.NOT_FOUND_AUTHENTICATION_INFO;
        response.setStatus(errorType.getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter()
                .write(objectMapper.writeValueAsString(new ExceptionDto(errorType)));
        response.getWriter().flush();
    }

    private void processLogout(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            com.sparta.codeplanet.product.entity.User user = userDetails.getUser();
            user.setRefresh(true);
            userRepository.save(user);

            UserRefreshToken userRefreshToken = refreshTokenRepository.findByUser(user);
            if (userRefreshToken != null) {
                userRefreshToken.invalidate(true);
                refreshTokenRepository.save(userRefreshToken);
            }
        }

        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                ApiResponse.success(SUCCESS_LOGOUT.getMessage())));
        response.getWriter().flush();

        // Log logout action
        log.info("User logged out successfully");
    }

    /**
     * Request Header 에서 토큰 정보 추출
     *
     * @param request
     * @return
     */
    private String resolveToken(HttpServletRequest request, String headerName) {
        String bearerToken = request.getHeader(headerName);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AuthEnum.GRANT_TYPE.getValue())) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

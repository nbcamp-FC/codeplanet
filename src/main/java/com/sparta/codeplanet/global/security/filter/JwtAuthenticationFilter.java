package com.sparta.codeplanet.global.security.filter;

import static com.sparta.codeplanet.global.enums.ResponseMessage.SUCCESS_LOGIN;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.global.exception.ExceptionDto;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.dto.LoginRequestDto;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final UserRefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManager authenticationManager;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // 인증이 필요 없는 URL을 지정합니다.
    private static final String[] AUTH_WHITELIST = {
        "/users",
        "/users/login",
        "/emails"
        // 추가적인 인증이 필요 없는 URL을 여기에 추가할 수 있습니다.
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

        // 요청 URI가 인증이 필요 없는 URL에 해당하는지 확인합니다.
        if (isWhitelisted(requestURI)) {
            if ("/users/login".equals(requestURI) && "POST".equalsIgnoreCase(request.getMethod())) {
                try {
                    attemptAuthentication(request, response);
                } catch (AuthenticationException e) {
                    unsuccessfulAuthentication(request, response, e);
                }
            }
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String accessToken = resolveToken(request, AuthEnum.ACCESS_TOKEN.getValue());
            User user = parseUserSpecification(accessToken);
            AbstractAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                user, accessToken, user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetails(request));
        } catch (ExpiredJwtException e) {
            reissueAccessToken(request, response, e);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 인증이 필요 없는 URL인지 확인합니다.
     *
     * @param requestURI
     * @return
     */
    private boolean isWhitelisted(String requestURI) {
        for (String url : AUTH_WHITELIST) {
            if (requestURI.startsWith(url)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Request Header 에서 토큰 정보 추출
     *
     * @param request
     * @return
     */
    private String resolveToken(HttpServletRequest request, String headerName) {
        String bearerToken = request.getHeader(headerName);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(
            AuthEnum.GRANT_TYPE.getValue())) {
            return bearerToken.substring(7);
        }
        return null;
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
            String refreshToken = resolveToken(request, "Refresh-Token");
            if (refreshToken == null) {
                throw exception;
            }
            String oldAccessToken = resolveToken(request, HttpHeaders.AUTHORIZATION);
            tokenProvider.validateRefreshToken(refreshToken, oldAccessToken);
            String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
            User user = parseUserSpecification(newAccessToken);
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(
                user, newAccessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            response.setHeader("New-Access-Token", newAccessToken);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
    }

    // 로그인 요청 처리
    public void attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException, IOException, ServletException {
        LoginRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(),
            LoginRequestDto.class);

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                requestDto.getUsername(),
                requestDto.getPassword()
            )
        );

        successfulAuthentication(request, response, authentication);
    }

    // 로그인 성공 처리
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, Authentication auth)
        throws IOException, ServletException {
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
        com.sparta.codeplanet.product.entity.User user = userDetails.getUser();

        // 탈퇴한 유저는 로그인이 불가하게 만듭니다.
        if (Status.DEACTIVATE.equals(user.getStatus())) {
            throw new CustomException(ErrorType.DEACTIVATE_USER);
        }

        String username = userDetails.getUsername();
        UserRole role = user.getUserRole();

        String accessToken = tokenProvider.createAccessToken(username, role);
        String refreshToken = tokenProvider.createRefreshToken(username, role);

        user.setRefresh(false);
        userRepository.save(user);

        response.addHeader(AuthEnum.ACCESS_TOKEN.getValue(), accessToken);
        response.addHeader(AuthEnum.REFRESH_TOKEN.getValue(), refreshToken);

        // 로그인 성공 메시지
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(
            SUCCESS_LOGIN));
        response.getWriter().flush();
    }

    // 로그인 실패 처리
    protected void unsuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, AuthenticationException failed)
        throws IOException, ServletException {
        ErrorType errorType = ErrorType.NOT_FOUND_AUTHENTICATION_INFO;
        response.setStatus(errorType.getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter()
            .write(new ObjectMapper().writeValueAsString(new ExceptionDto(errorType)));
        response.getWriter().flush();
    }
}

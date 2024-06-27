package com.sparta.codeplanet.global.config;

import com.sparta.codeplanet.global.security.UserDetailsServiceImpl;
import com.sparta.codeplanet.global.security.filter.JwtAuthenticationEntryPoint;
import com.sparta.codeplanet.global.security.filter.JwtAuthenticationFilter;
import com.sparta.codeplanet.global.security.filter.JwtAuthorizationFilter;
import com.sparta.codeplanet.global.security.filter.JwtExceptionFilter;
import com.sparta.codeplanet.global.security.jwt.TokenProvider;
import com.sparta.codeplanet.product.repository.UserRefreshTokenRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 지원을 가능하게 함
public class SecurityConfig {

    /**
     * TokenProvider 필드값 설정
     */
    private final TokenProvider tokenProvider;
    private final AuthenticationEntryPoint entryPoint;
    private final UserDetailsServiceImpl userDetailsService;
    private final UserRepository userRepository;
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    private final String[] WHITE_LIST = {"/users", "/user/login", "/feed/**"};

    /**
     * 암호화 매서드 빈 주입
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        return new JwtAuthenticationFilter(tokenProvider, userRepository, userRefreshTokenRepository, authenticationManager(authenticationConfiguration));
    }

    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(tokenProvider, userDetailsService);
    }

    @Bean
    public JwtExceptionFilter jwtExceptionFilter() {
        return new JwtExceptionFilter();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
        JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        /**
         *  폼을통한 로그인 방식 사용안함
         */
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http
                .authorizeHttpRequests(requests ->
                        requests.requestMatchers("/users", "/users/login", "/email/**").permitAll()	// requestMatchers의 인자로 전달된 url은 모두에게 허용
                                .requestMatchers(HttpMethod.GET, "/feed/**").permitAll()
                                .requestMatchers(HttpMethod.GET, "/users/{userId}/follower").permitAll() // 팔로워 조회
                                .requestMatchers(HttpMethod.GET, "/users/{userId}/following").permitAll() // 팔로잉 조회
                                .requestMatchers(HttpMethod.GET, "/feed/{{feedId}}/reply").permitAll() // 댓글 조회
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN") // admin
                                .anyRequest().authenticated()	// 그 외의 모든 요청은 인증 필요
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )   // 세션을 사용하지 않으므로 STATELESS 설정
                .exceptionHandling(handler-> handler.authenticationEntryPoint(entryPoint))
                .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(jwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtExceptionFilter(), JwtAuthorizationFilter.class);

        return http.build();
    }
}

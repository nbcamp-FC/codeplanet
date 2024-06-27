package com.sparta.codeplanet.product.controller;

import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.security.jwt.Tokens;
import com.sparta.codeplanet.product.dto.ApiResponse;
import com.sparta.codeplanet.product.dto.LoginRequestDto;
import com.sparta.codeplanet.product.dto.SignupRequestDto;
import com.sparta.codeplanet.product.service.AuthService;
import com.sparta.codeplanet.product.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
@Slf4j
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    @PostMapping
    public ApiResponse signUp(@RequestBody SignupRequestDto request) {
        return ApiResponse.success(userService.signup(request));
    }

//    @PostMapping("/login")
//    public ApiResponse login(@RequestBody LoginRequestDto request) {
//        return ApiResponse.success(authService.login(request.getUsername() , request.getPassword()));
//    }

//    @PostMapping("/reissue")
//    public ResponseEntity<Tokens> reissue(HttpServletRequest request,
//            HttpServletResponse response) {
//        String refreshToken = request.getHeader(AuthEnum.REFRESH_TOKEN.getValue());
//        Tokens token = authService.reissue(refreshToken);
//        response.setHeader(AuthEnum.ACCESS_TOKEN.getValue(), token.getAccessToken());
//        response.setHeader(AuthEnum.REFRESH_TOKEN.getValue(), token.getRefreshToken());
//        return ResponseEntity.ok(token);
//    }

//
//    @PostMapping("/logout")
//    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response,
//            Authentication authentication) {
//        authService.logout(request, response, authentication);
//        return ResponseEntity.ok("로그아웃완료");
//    }

}

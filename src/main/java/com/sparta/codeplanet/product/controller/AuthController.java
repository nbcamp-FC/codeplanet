package com.sparta.codeplanet.product.controller;

import com.sparta.codeplanet.global.enums.AuthEnum;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.product.dto.ApiResponse;
import com.sparta.codeplanet.product.dto.SignupRequestDto;
import com.sparta.codeplanet.product.service.AuthService;
import com.sparta.codeplanet.product.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    @PostMapping
    public ApiResponse signUp(@RequestBody SignupRequestDto request) {
        return ApiResponse.success(userService.signup(request));
    }

//    @PostMapping("/reissue")
//    public ApiResponse reissue(HttpServletRequest request,
//            HttpServletResponse response){
//        String refreshToken = request.getHeader(AuthEnum.REFRESH_TOKEN.getValue());
//        authService.reissue(refreshToken);
//    }

}

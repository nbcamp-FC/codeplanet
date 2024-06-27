package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.UserRole;

public record SignInResponseDto(
        String username,
        UserRole role,
        String accessToken,
        String refreshToken
) {
}

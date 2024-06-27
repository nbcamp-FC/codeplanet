package com.sparta.codeplanet.product.dto;

import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class EmailResponseDto {

    private String email;
    private String authCode;
    private LocalDateTime expiredAt;

    public EmailResponseDto(String email, String authCode, LocalDateTime expiredAt) {
        this.email = email;
        this.authCode = authCode;
        this.expiredAt = expiredAt;
    }
}

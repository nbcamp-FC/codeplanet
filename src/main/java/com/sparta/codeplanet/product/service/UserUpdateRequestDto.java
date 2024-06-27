package com.sparta.codeplanet.product.service;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
public class UserUpdateRequestDto {
    private String intro;
    @NotBlank
    private String nickname;

    // ture 들어오면 탈퇴
    private Boolean isTalTye;
}


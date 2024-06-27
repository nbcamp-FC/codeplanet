package com.sparta.codeplanet.global.security.jwt;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PACKAGE)
public class Tokens {
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private boolean expired;
}

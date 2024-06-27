package com.sparta.codeplanet.global.enums;


/**
 * 시큐리티관련 Enum 클래스
 */
public enum AuthEnum {

    AUTHORIZATION_KEY("auth"),
    ACCESS_TOKEN("AccessToken"),
    REFRESH_TOKEN("RefreshToken"),
    /**
     * @GRANT_TYPE Bearer
     */
    GRANT_TYPE("Bearer ");
    private String description;

    AuthEnum(String token) {
        this.description = token;
    }
    public String getValue() {
        return description;
    }
}

package com.sparta.codeplanet.product.entity;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.CustomException;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Entity
@Getter
@NoArgsConstructor
public class Email  {

    private static final Long MAX_EXPIRE_TIME = 3L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String authCode;

    @Column(nullable = false)
    private LocalDateTime expireDate;

    @Builder
    public Email(Long id, @NonNull String email, @NonNull String authCode) {
        this.id = id;
        this.email = email;
        this.authCode = authCode;
        this.expireDate = LocalDateTime.now().plusMinutes(MAX_EXPIRE_TIME);
    }

    /**
     * 인증 코드 검증
     * @param authCode 인증 코드
     */
    public void verifyAuthCode(String authCode) {

        if (!this.authCode.equals(authCode)) {
            throw new CustomException(ErrorType.WRONG_AUTH_CODE);
        }

        LocalDateTime now = LocalDateTime.now();
        if (ChronoUnit.SECONDS.between(this.expireDate, now) > MAX_EXPIRE_TIME * 60) {
            throw new CustomException(ErrorType.EXPIRED_AUTH_CODE);
        }
    }

    /**
     * 인증 코드 및 만료 시간 수정
     * @param authCode 인증 코드
     */
    public void updateAuthCode(String authCode) {
        this.authCode = authCode;
        this.expireDate = LocalDateTime.now().plusMinutes(MAX_EXPIRE_TIME);
    }
}

package com.sparta.codeplanet.product.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import jakarta.persistence.*;


@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserRefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "user_id")
    private User user;

    private String refreshToken;


    private int reissueCount = 0;

    @Column(nullable = false)
    private boolean isInvalid = false; // 무효화 필드 추가

    public UserRefreshToken(User user, String refreshToken) {
        this.user = user;
        this.refreshToken = refreshToken;
    }

    /**
     * refresh 토큰이 만료된 경우 재발급합니다.
     * @param refreshToken
     */
    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    /**
     * 토큰의 유효성을 검사합니다.
     * @param refreshToken
     * @return
     */
    public boolean validateRefreshToken(String refreshToken) {
        return !isInvalid && this.refreshToken.equals(refreshToken);
    }

    public void invalidate(boolean stat) {
        this.isInvalid = stat;
    }
    /**
     * reissue의 횟수를 측정하여 제한하기 위함입니다.
     */
    public void increaseReissueCount() {
        reissueCount++;
    }
}
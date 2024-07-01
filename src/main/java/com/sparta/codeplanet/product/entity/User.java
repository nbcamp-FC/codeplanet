package com.sparta.codeplanet.product.entity;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.global.exception.CustomException;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.mapping.ToOne;

import java.util.List;

@Entity
@Getter
@Table(name="User")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class User extends TimeStamp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "companyId", nullable = false)
    private Company company;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname;

    @Column
    private String intro;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private UserRole userRole = UserRole.USER;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Status status;

    @OneToMany(mappedBy = "fromUser", fetch = FetchType.LAZY)
    private List<Follow> followingList;

    @OneToMany(mappedBy = "toUser", fetch = FetchType.LAZY)
    private List<Follow> followerList;

    @Column
    private Boolean refresh;

    @Builder
    public User(String username,String nickname, String hashedPassword, String email,Company company, String intro, Status status) {
        this.username = username;
        this.password = hashedPassword;
        this.nickname = nickname;
        this.email = email;
        this.company = company;
        this.intro = intro;
        this.status = status;
    }
    public void checkPassword(String password) {
        if (!this.password.equals(password)) {
            throw new IllegalArgumentException("패스워드가 다릅니다.");
        }
    }
    // status를 수정하는 매서드 만들기
    public void setStatus(String statusString) {
        if (statusString.equals("탈퇴")) {
            status = Status.DEACTIVATE;
        }
    }

    public boolean setRefresh(Boolean refresh) {
        this.refresh = refresh;;
        return this.refresh;
    }

    /**
     * 회원 상태 검증 (이메일 인증)
     */
    public void verifyStatusWhenEmailAuth() {
        // 이미 승인된 회원
        if (Status.ACTIVE.equals(this.status)) {
            throw new CustomException(ErrorType.APPROVED_USER);
        }
        // 탈퇴한 회원
        if (Status.DEACTIVATE.equals(this.status)) {
            throw new CustomException(ErrorType.DEACTIVATED_USER);
        }
    }

    /**
     * 회원 상태 검증 (팔로우)
     */
    public void verifyStatusWhenFollow() {
        // 승인되지 않은 회원
        if (Status.BEFORE_APPROVE.equals(this.status)) {
            throw new CustomException(ErrorType.UNAPPROVED_USER);
        }
        // 탈퇴한 회원
        if (Status.DEACTIVATE.equals(this.status)) {
            throw new CustomException(ErrorType.DEACTIVATED_USER);
        }
    }

    /**
     * 회원 상태 변경 (ACTIVE)
     */
    public void active() {
        this.status = Status.ACTIVE;
    }

    /**
     * 회원 상태 변경 (DEACTIVATE)
     */
    public void deactivate() {
        this.status = Status.DEACTIVATE;
    }

    public void updateRole() {
        if (this.userRole == UserRole.USER) {
            this.userRole = UserRole.ADMIN;
        }else {
            this.userRole = UserRole.USER;
        }
    }

    public void updatePassword(String hashedPassword) {
        this.password = hashedPassword;
    }

    public void updateProfile(String nickname, String intro) {
        this.nickname = nickname;
        this.intro = intro;
    }
}
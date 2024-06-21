package com.sparta.codeplanet.product.entity;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.enums.UserRole;
import com.sparta.codeplanet.global.exception.CustomException;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Table(name="User")
@NoArgsConstructor
@AllArgsConstructor
public class User extends TimeStamp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

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

    @Column
    private Boolean refresh;

    @ManyToOne
    @JoinColumn(name = "companyId", nullable = false)
    private Company company;

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
     * 회원 상태 확인
     */
    public void verifyStatus() {
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
     * 회원 상태 변경
     * @param status
     */
    public void updateStatus(Status status) {
        this.status = status;
    }
}

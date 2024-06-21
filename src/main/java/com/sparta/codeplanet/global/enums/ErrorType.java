package com.sparta.codeplanet.global.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorType {

    DUPLICATE_ACCOUNT_ID(HttpStatus.LOCKED, "이미 아이디가 존재합니다."),
    NOT_EXISTS_USER(HttpStatus.BAD_REQUEST, "존재하지 않는 회원입니다."),
    NOT_FOUND_AUTHENTICATION_INFO(HttpStatus.UNAUTHORIZED, "ID 혹은 PASSWORD가 잘못되었습니다."),
    NOT_FOUND_USER(HttpStatus.NOT_FOUND, "존재하지 않는 회원입니다."),
    UNAPPROVED_USER(HttpStatus.LOCKED, "승인되지 않은 사용자입니다."),
    APPROVED_USER(HttpStatus.LOCKED, "이미 승인된 회원입니다."),
    DEACTIVATED_USER(HttpStatus.LOCKED, "탈퇴한 회원입니다."),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    DEACTIVATE_USER(HttpStatus.BAD_REQUEST, "활성화 되지 않은 유저입니다."),

    // email
    NOT_FOUND_AUTH_CODE(HttpStatus.NOT_FOUND, "인증 코드를 찾을 수 없습니다."),
    WRONG_AUTH_CODE(HttpStatus.LOCKED, "잘못된 인증 코드입니다."),
    EXPIRED_AUTH_CODE(HttpStatus.LOCKED, "만료된 인증 코드입니다."),

    // company
    UNREGISTERED_DOMAIN(HttpStatus.LOCKED, "등록되지 않은 도메인입니다."),


    // feed
    NOT_FOUND_FEED(HttpStatus.LOCKED, "게시물을 찾을 수 없습니다."),
    NOT_AUTHORIZED_UPDATE(HttpStatus.LOCKED, "이 게시물을 수정할 권한이 없습니다."),
    NOT_AUTHORIZED_DELETE(HttpStatus.LOCKED, "이 게시물을 삭제할 권한이 없습니다."),

    // follow
    CANNOT_FOLLOW_MYSELF(HttpStatus.FORBIDDEN, "자기 자신을 팔로우 할 수 없습니다."),
    DUPLICATE_FOLLOW(HttpStatus.LOCKED, "이미 팔로우한 회원입니다."),
    NOT_FOLLOWING(HttpStatus.LOCKED, "팔로우 한 상태가 아닙니다.");

    private final HttpStatus httpStatus;
    private final String message;
}


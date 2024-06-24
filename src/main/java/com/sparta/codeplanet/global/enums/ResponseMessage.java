package com.sparta.codeplanet.global.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ResponseMessage {
    SUCCESS(""),
    ERROR("유효하지 않은 접근입니다."),
    SEND_EMAIL_SUCCESS("승인 코드가 발송되었습니다."),
    VERIFY_AUTH_CODE_SUCCESS("회원가입 승인 처리되었습니다."),
    SUCCESS_LOGIN("로그인이 완료되었습니다."),
    SUCCESS_LOGOUT("로그아웃을 완료하였습니다."),
    FOLLOW_SUCCESS("님을 팔로우 하였습니다."),
    UNFOLLOW_SUCCESS("님을 언팔로우 하였습니다."),
    FOLLOWING_LIST("팔로잉 목록 조회에 성공하였습니다."),
    FOLLOWER_LIST("팔로워 목록 조회에 성공하였습니다."),

    FEED_UPDATE_SUCCESS("게시글을 수정하였습니다."),
    FEED_CREATE_SUCCESS("게시글을 작성하였습니다."),
    FEED_DELETE_SUCCESS("게시글을 삭제하였습니다."),
    FEED_READ_SUCCESS("게시물을 조회하였습니다."),

    ADD_REPLY_SUCCESS("댓글 작성 완료"),
    NO_EXIST_REPLY("댓글이 없습니다."),
    REPLY_READ_SUCCESS("댓글 조회 성공"),
    REPLY_DELETE_SUCCESS("댓글 삭제 성공"),
    REPLY_UPDATE_SUCCESS("댓글 수정 성공"),

    ADD_LIKE_TO_FEED_SUCCESS("피드 좋아요 성공"),
    CANCEL_LIKE_TO_FEED_SUCCESS("피드 좋아요 취소 성공"),
    ADD_LIKE_TO_REPLY_SUCCESS("댓글 좋아요 성공"),
    CANCEL_LIKE_TO_REPLY_SUCCESS("댓글 좋아요 취소 성공"),;

    private final String message;
}

package com.sparta.codeplanet.product.controller;

import com.sparta.codeplanet.global.enums.ResponseMessage;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.product.dto.FollowResponseDto;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.service.FollowService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class FollowController {

    private final FollowService followService;

    /**
     * 팔로우 추가
     * @param userId 팔로우 요청 받은 회원 ID
     * @return 팔로우 요청 받은 회원의 이름
     */
    @PostMapping("/follow/{userId}")
    public ResponseEntity<?> createFollow(
            @PathVariable Long userId,
            @AuthenticationPrincipal UserDetailsImpl userDetails) {

        String followUsername = followService.createFollow(userDetails.getUser(), userId);

        return ResponseEntity.ok(followUsername + ResponseMessage.FOLLOW.getMessage());
    }

    /**
     * 팔로잉 목록 조회
     * @param userId 팔로잉 목록 조회할 회원 ID
     * @return 팔로잉 목록
     */
    @GetMapping("/{userId}/following")
    public ResponseEntity<?> getFollowingList(
            @PathVariable Long userId,
            @AuthenticationPrincipal UserDetailsImpl userDetails) {

        List<FollowResponseDto> responseDtoList = followService.getFollowingList(userDetails.getUser(), userId);

        return ResponseEntity.ok(
                new ResponseEntityDto<>(ResponseMessage.FOLLOWING_LIST, responseDtoList));
    }

    /**
     * 팔로워 목록 조회
     * @param userId 팔로워 목록 조회할 회원 ID
     * @return 팔로워 목록
     */
    @GetMapping("/{userId}/follower")
    public ResponseEntity<?> getFollowerList(
            @PathVariable Long userId,
            @AuthenticationPrincipal UserDetailsImpl userDetails) {

        List<FollowResponseDto> responseDtoList = followService.getFollowerList(userDetails.getUser(), userId);

        return ResponseEntity.ok(
                new ResponseEntityDto<>(ResponseMessage.FOLLOWER_LIST, responseDtoList));
    }

    /**
     * 팔로우 취소
     * @param userId 팔로우 취소 당하는 회원
     * @return 팔로우 취소 당하는 회원 이름
     */
    @DeleteMapping("/follow/{userId}")
    public ResponseEntity<?> deleteFollow(
            @PathVariable Long userId,
            @AuthenticationPrincipal UserDetailsImpl userDetails) {
        log.info("Delete follow request for user: " + userDetails.getUser().getUsername());

        String unFollowUsername = followService.deleteFollow(userDetails.getUser(), userId);

        return ResponseEntity.ok(unFollowUsername + ResponseMessage.UNFOLLOW.getMessage());
    }
}

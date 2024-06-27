package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.FollowResponseDto;
import com.sparta.codeplanet.product.entity.Follow;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.FollowRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class FollowService {

    private final UserService userService;
    private final UserRepository userRepository;
    private final FollowRepository followRepository;

    /**
     * 팔로우 추가
     * @param fromUser 팔로우를 요청한 회원
     * @param userId 팔로우를 요청 받은 회원의 ID
     * @return 팔로우 요청 받은 회원의 이름
     */
    public String createFollow(User fromUser, Long userId) {
        User toUser = userService.getUserById(userId);
        toUser.verifyStatusWhenFollow();

        // 자기 자신 팔로우 시
        if (fromUser.getId().equals(toUser.getId())) {
            throw new CustomException(ErrorType.CANNOT_FOLLOW_MYSELF);
        }
        // 중복 팔로우 시
        if (followRepository.findByFromUserAndToUser(fromUser, toUser).isPresent()) {
            throw new CustomException(ErrorType.DUPLICATE_FOLLOW);
        }

        Follow follow = Follow.builder()
                .fromUser(fromUser)
                .toUser(toUser)
                .build();

        followRepository.save(follow);

        return toUser.getNickname();
    }

    /**
     * 팔로잉 목록 조회
     * @param user 로그인한 회원
     * @param userId 팔로잉 목록을 조회할 회원 ID
     * @return 팔로잉 목록
     */
    public List<FollowResponseDto> getFollowingList(User user, Long userId) {
        // 팔로잉 목록을 조회할 회원
        User fromUser = userService.getUserById(userId);

        // 팔로우 목록
        List<Follow> follows = fromUser.getFollowingList();

        // 팔로잉 목록
        List<FollowResponseDto> followingList = follows.stream()
                .map(Follow::getToUser)
                .filter(u -> Status.ACTIVE.equals(u.getStatus()))
                .map(FollowResponseDto::new)
                .toList();

        // 로그인한 회원이 팔로잉 목록 회원들을 팔로우했는지 여부
        followingList.forEach(response -> UserFollowedByLoggedInUser(response, user));

        return followingList;
    }

    /**
     * 팔로워 목록 조회
     * @param user 로그인한 회원
     * @param userId 팔로워 목록을 조회할 회원 ID
     * @return 팔로워 목록
     */
    public List<FollowResponseDto> getFollowerList(User user, Long userId) {
        // 팔로워 목록을 조회할 회원
        User toUser = userService.getUserById(userId);

        // 팔로우 목록
        List<Follow> follows = toUser.getFollowerList();

        // 팔로워 목록
        List<FollowResponseDto> followerList = follows.stream()
                .map(Follow::getFromUser)
                .filter(u -> Status.ACTIVE.equals(u.getStatus()))
                .map(FollowResponseDto::new)
                .toList();

        // 로그인한 회원이 팔로워 목록 회원들을 팔로우했는지 여부
        followerList.forEach(response -> UserFollowedByLoggedInUser(response, user));

        return followerList;
    }

    /**
     * 팔로우 취소
     * @param user 팔로우 취소하는 회원
     * @param userId 팔로우 취소 당하는 회원
     * @return 팔로우 취소 당하는 회원 이름
     */
    public String deleteFollow(User user, Long userId) {
        User toUser = userService.getUserById(userId);
        toUser.verifyStatusWhenFollow();

        log.info("deleteFollow : " + toUser.getNickname());

        Follow follow = followRepository.findByFromUserAndToUser(user, toUser)
                .orElseThrow(() -> new CustomException(ErrorType.NOT_FOLLOWING));

        followRepository.delete(follow);

        log.info("delete success");

        return toUser.getNickname();
    }

    /**
     * 로그인한 회원과 조회된 회원의 팔로우 관계 확인
     * @param response 팔로우 목록
     * @param loggedInUser 로그인한 회원
     */
    private void UserFollowedByLoggedInUser(FollowResponseDto response, User loggedInUser) {
        User user = userService.getUserById(response.getUserId());
        if (loggedInUser.getId().equals(user.getId())) {
            return;
        }

        response.setFollowStatus(
                followRepository.findByFromUserAndToUser(loggedInUser, user).isPresent());
    }
}

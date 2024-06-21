package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.enums.ResponseMessage;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.FeedRequestDto;
import com.sparta.codeplanet.product.dto.FeedResponseDto;
import com.sparta.codeplanet.product.dto.GroupFeedResponseDto;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.FeedRepository;
import com.sparta.codeplanet.product.repository.UserRepository;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FeedService {

    private final FeedRepository feedRepository;
    private final UserRepository userRepository;


    public FeedService(FeedRepository feedRepository, UserRepository userRepository) {
        this.feedRepository = feedRepository;
        this.userRepository = userRepository;
    }

    /**
     * 게시물 작성
     * @param requestDto 게시물
     * @param user       사용자 정보
     * @return 게시물 작성 내용 반환
     */
    @Transactional
    public FeedResponseDto createFeed(FeedRequestDto requestDto, User user) {
        Feed feed = new Feed(user, requestDto.getTitle(), requestDto.getContent(),
            requestDto.getStatus());
        Feed savedFeed = feedRepository.save(feed);
        return new FeedResponseDto(savedFeed);
    }

    /**
     * 게시물 조회
     * @param page 페이지수
     * @param size 사이즈
     * @return 게시물 조회
     */
    @Transactional(readOnly = true)
    public Page<FeedResponseDto> getFeeds(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        return feedRepository.findAll(pageable)
            .map(FeedResponseDto::new); // `Page<Feed>`를 `Page<FeedResponseDto>`로 변환
    }

    /**
     * 게시물 수정
     * @param feedId     게시물 아이디
     * @param requestDto 게시물 엔티티 정보
     * @param user       사용자 엔티티 정보
     * @return 게시물 수정한 거 반환
     * @throws CustomException 게시물 여부와 사용자 검증
     */
    @Transactional
    public ResponseEntityDto<FeedResponseDto> updateFeed(Long feedId, FeedRequestDto requestDto,
        User user) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));
        // 작성자 본인만 수정 가능
        if (!feed.getUser().getId().equals(user.getId())) {
            throw new CustomException(ErrorType.NOT_AUTHORIZED_UPDATE);
        }
        feed.update(requestDto.getTitle(), requestDto.getContent());
        FeedResponseDto feedResponse = new FeedResponseDto(feed);
        return new ResponseEntityDto<>(ResponseMessage.FEED_UPDATE_SUCCESS, feedResponse);
    }

    /**
     * 게시물 삭제
     * @param userId 사용자 아이디
     * @param feedId 게시물 아이디
     * @throws CustomException 게시물 존재 여부, 사용자 검증
     * @return 게시물 삭제 응답 반환
     */
    @Transactional
    public ResponseEntityDto<Void> deleteFeed(Long userId, Long feedId) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        // 작성자 검증
        if (!feed.getUser().getId().equals(userId)) {
            throw new CustomException(ErrorType.NOT_AUTHORIZED_DELETE);
        }

        feedRepository.delete(feed);
        return new ResponseEntityDto<>(ResponseMessage.FEED_DELETE_SUCCESS, null);
    }

    /**
     * 소속별 게시물 조회
     * @param userId 사용자 아이디
     * @param page 페이지 수
     * @param size 사이즈
     * @throws CustomException 사용자 검증
     * @return 게시물 조회 반환
     */
    @Transactional(readOnly = true)
    public List<GroupFeedResponseDto> getFeedsByUserCompany(Long userId, int page, int size) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));

        return feedRepository.findByUser_Company(user.getCompany(), pageable)
            .getContent()
            .stream()
            .map(GroupFeedResponseDto::new)
            .collect(Collectors.toList());
    }
}

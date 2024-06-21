package com.sparta.codeplanet.product.controller;


import com.sparta.codeplanet.global.enums.ResponseMessage;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.product.dto.FeedRequestDto;
import com.sparta.codeplanet.product.dto.FeedResponseDto;
import com.sparta.codeplanet.product.dto.GroupFeedResponseDto;
import com.sparta.codeplanet.product.dto.PageableResponse;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.service.FeedService;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/feed")
public class FeedController {

    private final FeedService feedService;

    public FeedController(FeedService feedService) {
        this.feedService = feedService;
    }

    /**
     * 게시물 작성
     * @param requestDto 게시물
     * @return 게시물 작성 메시지와 게시물 작성 내용 반환
     */
    @PostMapping
    public ResponseEntity<ResponseEntityDto<FeedResponseDto>> createFeed(
        @RequestBody FeedRequestDto requestDto,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        FeedResponseDto responseDto = feedService.createFeed(requestDto, userDetails.getUser());
        ResponseEntityDto<FeedResponseDto> responseEntity = new ResponseEntityDto<>(ResponseMessage.FEED_CREATE_SUCCESS, responseDto);
        return ResponseEntity.ok(responseEntity);
    }

    /**
     * 게시물 조회
     * @param page 페이지 수
     * @param size 사이즈
     * @return 게시물 내용 반환
     */
    @GetMapping
    public ResponseEntity<PageableResponse<FeedResponseDto>> getFeeds(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "5") int size) {
        Page<FeedResponseDto> responseDto = feedService.getFeeds(page, size);
        PageableResponse<FeedResponseDto> responseEntity = new PageableResponse<>(responseDto);
        return ResponseEntity.ok(responseEntity);
    }
    
    /**
     * 게시물 조회
     * @param requestDto 게시물 정보
     * @return 게시물 수정 내용 반환
     */
    @PutMapping("/{feedId}")
    public ResponseEntity<ResponseEntityDto<FeedResponseDto>> updateFeed(
        @PathVariable Long feedId,
        @RequestBody FeedRequestDto requestDto,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        FeedResponseDto responseDto = feedService.updateFeed(feedId, requestDto, userDetails.getUser())
            .getData();
        ResponseEntityDto<FeedResponseDto> responseEntity = new ResponseEntityDto<>(ResponseMessage.FEED_UPDATE_SUCCESS, responseDto);
        return ResponseEntity.ok(responseEntity);
    }
    
    /**
     * 게시물 삭제
     */
    @DeleteMapping("/{feedId}")
    public ResponseEntity<ResponseEntityDto<Void>> deleteFeed(
        @PathVariable Long feedId,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        ResponseEntityDto<Void> responseEntity = feedService.deleteFeed(feedId, userDetails.getUser().getId());
        return ResponseEntity.ok(responseEntity);
    }
    
    /**
     * 소속별 게시물 조회
     * @param page 페이지 수
     * @param size 사이즈
     * @return 게시물 조회
     */
    @GetMapping("/group")
    public ResponseEntity<List<GroupFeedResponseDto>> getFeedsByUserCompany(
        @AuthenticationPrincipal UserDetailsImpl userDetails,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "5") int size) {
        List<GroupFeedResponseDto> responseDto = feedService.getFeedsByUserCompany(userDetails.getUser().getId(), page, size);
        return ResponseEntity.ok(responseDto);
    }

    

}

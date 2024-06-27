package com.sparta.codeplanet.product.controller;

import com.sparta.codeplanet.global.enums.ResponseMessage;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.product.dto.ReplyRequestDto;
import com.sparta.codeplanet.product.dto.ReplyResponseDto;
import com.sparta.codeplanet.product.dto.ResponseEntityDto;
import com.sparta.codeplanet.product.service.ReplyService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/feed/{feedId}")
public class ReplyController {

    private final ReplyService replyService;

    public ReplyController(ReplyService replyService) {
        this.replyService = replyService;
    }

    /**
     * 댓글 작성
     * @param feedId
     * @param replyRequestDto
     * @param userDetails
     * @return 상태 코드, 메시지, 댓글 작성 정보
     */
    @PostMapping("/reply")
    public ResponseEntity<?> createReply(@PathVariable("feedId") long feedId,
        @RequestBody ReplyRequestDto replyRequestDto,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {

//        return ResponseEntity.ok(
//            HttpResponseDto.builder()
//                .statusCode(HttpStatus.OK.value())
//                .message("댓글 작성 완료")
//                .data(replyService.createReply(feedId, replyRequestDto, userDetails.getUser()))
//                .build()
//        );
        return ResponseEntity.ok(
                new ResponseEntityDto<>(
                        ResponseMessage.ADD_REPLY_SUCCESS,
                        replyService.createReply(feedId, replyRequestDto, userDetails.getUser())
                )
        );
    }

    /**
     * 댓글 조회
     * @param feedId
     * @return 상태 코드, 메시지, 댓글 정보
     */
    @GetMapping("/reply")
    public ResponseEntity<?> getReplies(@PathVariable("feedId") long feedId) {
        List<ReplyResponseDto> replies = replyService.findRepliesAll(feedId);
        if (replies.isEmpty()) {
            return ResponseEntity.ok(
//                HttpResponseDto.builder()
//                    .statusCode(HttpStatus.OK.value())
//                    .message("댓글이 없습니다.")
//                    .build()
                    new ResponseEntityDto<>(
                            ResponseMessage.NO_EXIST_REPLY
                    )
            );
        } else {
            return ResponseEntity.ok(
//                HttpResponseDto.builder()
//                    .statusCode(HttpStatus.OK.value())
//                    .message("댓글 조회 완료")
//                    .data(replies)
//                    .build()
                    new ResponseEntityDto<>(
                            ResponseMessage.REPLY_READ_SUCCESS,
                            replies
                    )
            );
        }
    }


    /**
     * 댓글 삭제
     * @param feedId
     * @param replyId
     * @param userDetails
     * @return 상태코드, 메시지
     */
    @DeleteMapping("/reply/{replyId}")
    public ResponseEntity<?> deleteReply(@PathVariable("feedId") long feedId,
        @PathVariable("replyId") long replyId,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        replyService.deleteReply(feedId, replyId, userDetails.getUser());
        return ResponseEntity.ok(
//            HttpResponseDto.builder()
//                .statusCode(HttpStatus.OK.value())
//                .message("댓글 삭제 완료")
//                .build()
                new ResponseEntityDto<>(
                        ResponseMessage.REPLY_DELETE_SUCCESS
                )
        );
    }

    /**
     * 댓글 수정
     * @param feedId
     * @param replyId
     * @param requestDto
     * @param userDetails
     * @return 상태코드, 메시지, 수정된 댓글 정보
     */
    @PatchMapping("/reply/{replyId}")
    public ResponseEntity<?> updateReply(@PathVariable("feedId") long feedId,
        @PathVariable("replyId") long replyId,
        @RequestBody ReplyRequestDto requestDto,
        @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return ResponseEntity.ok(
//            HttpResponseDto.builder()
//                .statusCode(HttpStatus.OK.value())
//                .message("댓글 수정이 완료되었습니다.")
//                .data(replyService.updateReply(feedId, replyId, requestDto, userDetails.getUser()))
//                .build()
                new ResponseEntityDto<>(
                        ResponseMessage.REPLY_UPDATE_SUCCESS,
                        replyService.updateReply(feedId, replyId, requestDto, userDetails.getUser())
                )
        );
    }
}

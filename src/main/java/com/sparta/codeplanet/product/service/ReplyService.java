package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.product.dto.ReplyRequestDto;
import com.sparta.codeplanet.product.dto.ReplyResponseDto;
import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.Reply;
import com.sparta.codeplanet.product.entity.User;
import com.sparta.codeplanet.product.repository.FeedRepository;
import com.sparta.codeplanet.product.repository.ReplyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ReplyService {

    private final ReplyRepository replyRepository;
    private final FeedRepository feedRepository;

    public ReplyResponseDto createReply(long feedId, ReplyRequestDto replyRequestDto, User user) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        Reply reply = new Reply(replyRequestDto, feed, user);
        Reply saveReply = replyRepository.save(reply);

        return new ReplyResponseDto(saveReply);
    }

    public void deleteReply(long feedId, long replyId, User user) {
        Reply reply = replyRepository.findById(replyId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_REPLY));

        if (reply.getUser().getId() != user.getId()) {
            throw new CustomException(ErrorType.WRONG_USER_REPLY);
        }
        replyRepository.delete(reply);
    }

    @Transactional
    public ReplyResponseDto updateReply(long feedId, long replyId, ReplyRequestDto requestDto,
        User user) {
        Reply reply = replyRepository.findById(replyId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_REPLY));

        if (reply.getUser().getId() != user.getId()) {
            throw new CustomException(ErrorType.WRONG_USER_REPLY);
        }
        reply.update(requestDto);
        return new ReplyResponseDto(reply);
    }

    public List<ReplyResponseDto> findRepliesAll(long feedId) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        return replyRepository.findAllByFeedId(feed.getId()).stream()
                .map(ReplyResponseDto::new)
                .toList();
    }

}

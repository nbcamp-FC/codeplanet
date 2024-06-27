package com.sparta.codeplanet.product.service;

import com.sparta.codeplanet.global.enums.ErrorType;
import com.sparta.codeplanet.global.exception.CustomException;
import com.sparta.codeplanet.global.security.UserDetailsImpl;
import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.Reply;
import com.sparta.codeplanet.product.entity.likes.FeedLikes;
import com.sparta.codeplanet.product.entity.likes.ReplyLikes;
import com.sparta.codeplanet.product.repository.FeedRepository;
import com.sparta.codeplanet.product.repository.ReplyRepository;
import com.sparta.codeplanet.product.repository.likes.FeedLikesRepository;
import com.sparta.codeplanet.product.repository.likes.ReplyLikesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class LikesService {

    private final FeedLikesRepository feedLikesRepository;
    private final ReplyLikesRepository replyLikesRepository;
    private final FeedRepository feedRepository;
    private final ReplyRepository replyRepository;

    @Transactional
    public int likeFeed(long feedId, UserDetailsImpl userDetails) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        if (feed.getUser().getId().equals(userDetails.getUser().getId())) {
            throw new CustomException(ErrorType.SAME_USER_FEED);
        }

        if (feedLikesRepository.findByFeedIdAndUserId(feedId, userDetails.getUser().getId()).isPresent()) {
            throw new CustomException(ErrorType.DUPLICATE_LIKE);
        }

        feedLikesRepository.save(new FeedLikes(feed,userDetails.getUser()));

        return feed.increaseLikesCount();
    }

    @Transactional
    public int unlikeFeed(long feedId, UserDetailsImpl userDetails) {
        Feed feed = feedRepository.findById(feedId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_FEED));

        FeedLikes feedLikes = feedLikesRepository
                .findByFeedIdAndUserId(feedId, userDetails.getUser().getId())
                .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_LIKE));

        feedLikesRepository.delete(feedLikes);

        return feed.decreaseLikesCount();
    }

    @Transactional
    public int likeReply(long replyId, UserDetailsImpl userDetails) {
        Reply reply = replyRepository.findById(replyId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_REPLY));

        if (reply.getUser().getId().equals(userDetails.getUser().getId())) {
            throw new CustomException(ErrorType.SAME_USER_REPLY);
        }

        if (replyLikesRepository.findByReplyIdAndUserId(replyId, userDetails.getUser().getId()).isPresent()) {
            throw new CustomException(ErrorType.DUPLICATE_LIKE);
        }

        replyLikesRepository.save(new ReplyLikes(reply,userDetails.getUser()));

        return reply.increaseLikesCount();
    }

    @Transactional
    public int unlikeReply(long replyId, UserDetailsImpl userDetails) {
        Reply reply = replyRepository.findById(replyId)
            .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_REPLY));

        ReplyLikes replyLikes = replyLikesRepository
                .findByReplyIdAndUserId(replyId, userDetails.getUser().getId())
                .orElseThrow(() -> new CustomException(ErrorType.NOT_FOUND_LIKE));

        replyLikesRepository.delete(replyLikes);

        return reply.decreaseLikesCount();
    }



}

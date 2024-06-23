package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.product.entity.Reply;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class ReplyResponseDto {

    private long id;
    private String content;
    private long feedId;
    private long userId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private int likeCount;

    public ReplyResponseDto(Reply reply) {
        this.id = reply.getId();
        this.content = reply.getContent();
        this.createdAt = reply.getCreatedAt();
        this.updatedAt = reply.getUpdatedAt();
        this.feedId = reply.getFeed().getId();
        this.userId = reply.getUser().getId();
        this.likeCount = reply.getLikesCount();
    }

}

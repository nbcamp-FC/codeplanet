package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.product.entity.Feed;
import lombok.Getter;

@Getter
public class FeedResponseDto {
    private Long id;
    private String title;
    private String content;
    private String user;
    private Status status;

    public FeedResponseDto(Feed feed) {
        this.id = feed.getId();
        this.title = feed.getTitle();
        this.content = feed.getContent();
        this.user = feed.getUser().getUsername();
        this.status = feed.getStatus();
    }
}

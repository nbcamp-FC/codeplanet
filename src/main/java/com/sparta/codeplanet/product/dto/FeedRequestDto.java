package com.sparta.codeplanet.product.dto;

import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.User;
import lombok.Getter;
import lombok.Setter;

@Getter
public class FeedRequestDto {
    private String title;
    private String content;
    private Status status;

    public Feed toEntity(User user) {
        return Feed.builder()
            .user(user)
            .title(title)
            .content(content)
            .status(status != null ? status : Status.ACTIVE)
            .build();

    }
}

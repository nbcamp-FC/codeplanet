package com.sparta.codeplanet.product.entity.likes;

import com.sparta.codeplanet.product.entity.Feed;
import com.sparta.codeplanet.product.entity.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Table(name = "feedLikes")
@NoArgsConstructor
public class FeedLikes {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "likeId")
    private long id;

    @ManyToOne
    @JoinColumn(name = "userId")
    private User user;

    @ManyToOne
    @JoinColumn(name = "feedId")
    private Feed feed;

    public FeedLikes(Feed feed, User user) {
        this.feed = feed;
        this.user = user;
    }
}

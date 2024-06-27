package com.sparta.codeplanet.product.entity;

import com.sparta.codeplanet.global.enums.Status;
import com.sparta.codeplanet.product.entity.likes.FeedLikes;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Feed extends TimeStamp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, unique = true)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "userId", nullable = false)
    private User user;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String content;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Status status = Status.ACTIVE;

    @OneToMany(mappedBy = "feed", fetch = FetchType.LAZY)
    private List<FeedLikes> likesList;

    @Column
    private Integer likesCount = 0;

    @Builder
    public Feed(User user, String title, String content, Status status) {
        this.user = user;
        this.title = title;
        this.content = content;
        this.status = status != null ? status : Status.ACTIVE;

    }

    public void update(String title, String content) {
        this.title = title;
        this.content = content;
    }

    public int increaseLikesCount() {
        return ++likesCount;
    }

    public int decreaseLikesCount() {
        return --likesCount;
    }
}
